#!/usr/bin/env bash
# run-tour.sh — render the master tour + the 12 supporting tapes
# (11..22) and stitch them into a single demo/recordings/00-octravpn-
# tour.mp4 via ffmpeg.
#
# Idempotent: re-running re-renders tapes whose .tape mtime is newer
# than the corresponding .mp4 in demo/recordings/. The stitched
# 00-octravpn-tour.mp4 is always re-built (it's cheap once the
# inputs exist).
#
# Exit codes:
#   0  every tape rendered + the stitch succeeded
#   1  vhs or ffmpeg missing — install hint printed
#   2  one or more tapes failed to render
#   3  ffmpeg concat step failed
#
# Usage:
#   demo/run-tour.sh           # render everything + stitch
#   demo/run-tour.sh --tapes   # render only; skip the stitch step
#   demo/run-tour.sh --stitch  # stitch from existing recordings; skip render

set -euo pipefail
cd "$(dirname "$0")/.."

MODE="all"
case "${1:-}" in
    --tapes)  MODE="tapes" ;;
    --stitch) MODE="stitch" ;;
    "")       ;;
    *)        echo "usage: $0 [--tapes|--stitch]" >&2; exit 1 ;;
esac

# Tool preflight — both required for the full pipeline. Light-job CI
# can short-circuit with --tapes if it only has vhs.
need_vhs=true
need_ffmpeg=true
[[ "$MODE" == "stitch" ]] && need_vhs=false
[[ "$MODE" == "tapes"  ]] && need_ffmpeg=false

if $need_vhs && ! command -v vhs >/dev/null 2>&1; then
    echo "install vhs: brew install vhs  (or download from https://github.com/charmbracelet/vhs)" >&2
    exit 1
fi
if $need_ffmpeg && ! command -v ffmpeg >/dev/null 2>&1; then
    echo "install ffmpeg: brew install ffmpeg  (or apt-get install ffmpeg)" >&2
    exit 1
fi

mkdir -p demo/recordings

# Ordered list — same order as the master-tour narrative arc, with
# the supporting tapes interleaved so the stitched mp4 reads as a
# coherent story rather than an alphabetical dump.
TAPES=(
    00-master-tour
    17-operator-onboarding
    18-tailnet-owner-policy
    11-user-install-linux
    12-user-install-macos
    13-user-ssh-peer
    14-user-web-traffic
    15-user-oct-url-public
    16-user-oct-url-sealed
    19-circle-update-atomic
    20-pvac-rotation
    21-audit-verify
    22-headscale-cli-tour
)

declare -a fail_list=()
if [[ "$MODE" != "stitch" ]]; then
    for name in "${TAPES[@]}"; do
        tape="demo/tapes/${name}.tape"
        mp4="demo/recordings/${name}.mp4"
        if [[ -f "$mp4" && "$mp4" -nt "$tape" ]]; then
            echo "=== ${name}: up-to-date (skipping)"
            continue
        fi
        echo "=== ${name}: rendering"
        if ! vhs "$tape"; then
            echo "  ! ${name} failed" >&2
            fail_list+=("${name}")
        fi
    done
fi

if (( ${#fail_list[@]} > 0 )); then
    echo
    echo "failed tapes:"
    printf '  - %s\n' "${fail_list[@]}"
    exit 2
fi

if [[ "$MODE" == "tapes" ]]; then
    exit 0
fi

# Stitch every available mp4 into the canonical tour. ffmpeg concat
# demuxer needs a file list with `file '...'` lines.
concat_list=$(mktemp -t octravpn-tour-concat.XXXXXX)
trap 'rm -f "$concat_list"' EXIT

for name in "${TAPES[@]}"; do
    mp4="demo/recordings/${name}.mp4"
    if [[ -f "$mp4" ]]; then
        printf "file '%s/%s'\n" "$PWD" "$mp4" >> "$concat_list"
    else
        echo "  ! ${mp4} missing — skipping from stitch" >&2
    fi
done

out=demo/recordings/00-octravpn-tour.mp4
echo "=== stitching ${out}"
if ! ffmpeg -y -f concat -safe 0 -i "$concat_list" -c copy "$out" 2>&1 | tail -20; then
    echo "  ! ffmpeg concat failed" >&2
    exit 3
fi

echo
echo "done: ${out}"
ls -lh "$out"
