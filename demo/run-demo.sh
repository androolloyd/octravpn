#!/usr/bin/env bash
# Regenerate every .tape's outputs in demo/recordings/.
# Skips tapes whose REQUIRES couldn't be satisfied (e.g. no Docker, no
# vhs binary installed). Emits a summary at the end.
#
# Usage:
#   demo/run-demo.sh                 # render every tape
#   demo/run-demo.sh 03-audit        # render the first matching tape
#
# Exit codes:
#   0  every requested tape rendered (or only the skipped ones failed)
#   1  vhs binary missing — install with `brew install vhs`
#   2  one or more requested tapes failed to render

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v vhs >/dev/null 2>&1; then
    echo "install vhs: brew install vhs" >&2
    exit 1
fi

mkdir -p recordings

filter="${1:-}"
declare -a ok_list=()
declare -a fail_list=()

shopt -s nullglob
for tape in tapes/*.tape; do
    if [[ -n "${filter}" && "${tape}" != *"${filter}"* ]]; then
        continue
    fi
    echo "=== ${tape} ==="
    if vhs "${tape}"; then
        ok_list+=("${tape}")
    else
        echo "  ! failed: ${tape}" >&2
        fail_list+=("${tape}")
    fi
done

echo
echo "outputs in demo/recordings/"
ls -lh recordings/ 2>/dev/null || true

echo
echo "rendered:  ${#ok_list[@]}"
echo "failed:    ${#fail_list[@]}"
if (( ${#fail_list[@]} > 0 )); then
    printf '  - %s\n' "${fail_list[@]}"
    exit 2
fi
