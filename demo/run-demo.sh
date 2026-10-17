#!/usr/bin/env bash
# Regenerate every .tape's outputs in demo/recordings/.
# Preflight each executable tape, render, then check its declared outputs.
#
# Usage:
#   demo/run-demo.sh                 # render every tape
#   demo/run-demo.sh 03-audit        # render the first matching tape
#
# Exit codes:
#   0  every requested tape rendered
#   1  vhs binary missing — install with `brew install vhs`
#   2  one or more requested tapes failed to render

set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v vhs >/dev/null 2>&1; then
    echo "install vhs: brew install vhs" >&2
    exit 1
fi

mkdir -p demo/recordings

filter="${1:-}"
declare -a ok_list=()
declare -a fail_list=()

shopt -s nullglob
for tape in demo/tapes/*.tape; do
    if [[ -n "${filter}" && "${tape}" != *"${filter}"* ]]; then
        continue
    fi
    echo "=== ${tape} ==="
    # The two install tapes contain instructions only. The two integration
    # wrappers run their own checks; all other tapes need command preflight.
    case "$(basename "$tape")" in
        05-*|06-*|11-*|12-*) ;;
        *)
            if ! bash demo/lib/preflight-tape.sh "$tape"; then
                fail_list+=("${tape}")
                continue
            fi
            ;;
    esac
    if vhs "${tape}"; then
        outputs_ok=1
        while read -r output; do
            if [[ ! -s "$output" ]]; then outputs_ok=0; fi
        done < <(awk '$1 == "Output" {print $2}' "$tape")
        if (( outputs_ok == 0 )); then
            fail_list+=("${tape}")
            continue
        fi
        ok_list+=("${tape}")
    else
        echo "  ! failed: ${tape}" >&2
        fail_list+=("${tape}")
    fi
done

echo
echo "outputs in demo/recordings/"

echo
echo "rendered:  ${#ok_list[@]}"
echo "failed:    ${#fail_list[@]}"
if (( ${#fail_list[@]} > 0 || ${#ok_list[@]} == 0 )); then
    printf '  - %s\n' "${fail_list[@]}"
    exit 2
fi
