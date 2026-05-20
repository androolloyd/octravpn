#!/usr/bin/env bash
# demo/lib/render-with-captions.sh
#
# Merge VHS-rendered .mp4 recordings with their sibling .vtt subtitle
# files into a single captioned .mp4. VHS does not natively emit
# subtitles, so each `demo/tapes/<NN>-name.tape` has a hand-authored
# `demo/recordings/<NN>-name.vtt` file (see scripts/gen_vtts.py and
# docs/demo.md §"Captions"). This script walks every tape, looks for
# the matching .mp4 + .vtt pair, and produces:
#
#     demo/recordings/<NN>-name-captioned.mp4
#
# The output uses `-c copy` for the video/audio streams and embeds the
# .vtt as an mov_text subtitle track, so it is playable in any HTML5
# <video> tag, mpv, VLC, or QuickTime.
#
# Usage:
#     demo/lib/render-with-captions.sh                # all tapes
#     demo/lib/render-with-captions.sh 06-tailscale   # one substring filter
#
# Requires: ffmpeg on PATH.

set -euo pipefail

# Resolve repo root from this script's location (demo/lib/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TAPES_DIR="${REPO_ROOT}/demo/tapes"
RECORDINGS_DIR="${REPO_ROOT}/demo/recordings"

FILTER="${1:-}"

if ! command -v ffmpeg >/dev/null 2>&1; then
    echo "render-with-captions: ffmpeg not on PATH" >&2
    exit 2
fi

if [[ ! -d "${TAPES_DIR}" ]]; then
    echo "render-with-captions: ${TAPES_DIR} does not exist" >&2
    exit 2
fi

shopt -s nullglob
ok=0
skipped=0
failed=0
total=0

for tape in "${TAPES_DIR}"/*.tape; do
    base="$(basename "${tape}" .tape)"
    if [[ -n "${FILTER}" && "${base}" != *"${FILTER}"* ]]; then
        continue
    fi
    total=$((total + 1))

    mp4="${RECORDINGS_DIR}/${base}.mp4"
    vtt="${RECORDINGS_DIR}/${base}.vtt"
    out="${RECORDINGS_DIR}/${base}-captioned.mp4"

    if [[ ! -f "${mp4}" ]]; then
        echo "skip ${base}: no .mp4 at ${mp4}" >&2
        skipped=$((skipped + 1))
        continue
    fi
    if [[ ! -f "${vtt}" ]]; then
        echo "skip ${base}: no .vtt at ${vtt}" >&2
        skipped=$((skipped + 1))
        continue
    fi

    echo "=== ${base} ==="
    # -c copy keeps the existing h.264 video without re-encoding.
    # -c:s mov_text embeds the .vtt as an mp4-compatible subtitle track.
    # -metadata:s:s:0 makes the track default-language English.
    if ffmpeg -y \
            -i "${mp4}" \
            -i "${vtt}" \
            -map "0:v" -map "0:a?" -map "1:0" \
            -c:v copy -c:a copy -c:s mov_text \
            -metadata:s:s:0 language=eng \
            -metadata:s:s:0 title="narrator" \
            "${out}" </dev/null >/dev/null 2>&1; then
        echo "  -> ${out}"
        ok=$((ok + 1))
    else
        echo "  ! ffmpeg failed for ${base}" >&2
        failed=$((failed + 1))
    fi
done

echo
echo "render-with-captions: total=${total} ok=${ok} skipped=${skipped} failed=${failed}"

if [[ ${failed} -gt 0 ]]; then
    exit 1
fi
exit 0
