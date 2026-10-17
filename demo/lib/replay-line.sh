#!/usr/bin/env bash
# replay-line.sh — `say` helper for fast-cut demo tapes.
#
# Usage in a tape (vhs):
#   Type 'source demo/lib/replay-line.sh'
#   Enter
#   Type 'say "bash demo/lib/devnet-bringup.sh" demo/captures/master-tour/01.txt'
#   Enter
#
# `say` prints a fake shell prompt + the command verbatim, then cats
# the pre-recorded capture file. Renders deterministically in <100ms
# instead of waiting on a real docker exec, which keeps tapes inside
# the 30s ceiling without losing the typed-command-then-output look.
#
# Captures must include their qualification provenance. This helper only
# replays recorded output; it does not execute the displayed command.

# shellcheck disable=SC2034
say() {
    local cmd="$1"
    local capture="$2"
    printf '$ %s\n' "$cmd"
    if [[ -z "${capture:-}" || ! -s "${capture}" ]]; then
        printf 'missing capture: %s\n' "${capture}" >&2
        return 1
    fi
    cat "${capture}"
}
export -f say
