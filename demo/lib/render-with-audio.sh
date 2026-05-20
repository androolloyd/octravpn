#!/usr/bin/env bash
# demo/lib/render-with-audio.sh
#
# Generate a TTS voiceover audio track from each tape's sibling .vtt
# subtitle file, then mux it onto the VHS-rendered .mp4 so the recording
# has a narrator track. Pair this with render-with-captions.sh when you
# want the final cut to carry both subtitles AND audio.
#
# Pipeline per tape:
#
#   1.  Parse <NN>.vtt → (start_seconds, text) tuples.
#   2.  Synthesize each cue with the available TTS backend:
#         macOS:  /usr/bin/say -o cue.aiff "<text>"
#         linux:  espeak-ng -w cue.wav    "<text>"
#         linux:  piper      -f cue.wav   (if piper + a model is present)
#       Each cue becomes one short audio file in a per-tape scratch dir.
#   3.  Stitch the cue files onto a silent timeline of the right total
#       length using ffmpeg's `adelay` per-cue + `amix` to combine, then
#       trim to the source mp4's duration. The result is one continuous
#       voiceover.wav at the same length as the video.
#   4.  Mux that voiceover onto the source mp4 with `-c:v copy -c:a aac`,
#       writing <NN>-narrated.mp4. If <NN>-captioned.mp4 already exists
#       (from render-with-captions.sh) we layer audio on top of it
#       instead, producing <NN>-narrated-captioned.mp4 with subtitle
#       track + voiceover in a single file.
#
# Usage:
#     demo/lib/render-with-audio.sh                # all tapes
#     demo/lib/render-with-audio.sh 06-tailscale   # one substring filter
#     OCTRA_TTS=espeak-ng demo/lib/render-with-audio.sh   # force backend
#
# Requires: ffmpeg + python3 on PATH, plus a TTS backend.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TAPES_DIR="${REPO_ROOT}/demo/tapes"
RECORDINGS_DIR="${REPO_ROOT}/demo/recordings"

FILTER="${1:-}"

if ! command -v ffmpeg >/dev/null 2>&1; then
    echo "render-with-audio: ffmpeg not on PATH" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "render-with-audio: python3 not on PATH" >&2
    exit 2
fi

# ---- pick a TTS backend --------------------------------------------------
TTS="${OCTRA_TTS:-}"
if [[ -z "${TTS}" ]]; then
    if command -v say          >/dev/null 2>&1; then TTS="say"
    elif command -v espeak-ng  >/dev/null 2>&1; then TTS="espeak-ng"
    elif command -v espeak     >/dev/null 2>&1; then TTS="espeak"
    elif command -v piper      >/dev/null 2>&1 && [[ -n "${PIPER_MODEL:-}" ]]; then
        TTS="piper"
    else
        echo "render-with-audio: no TTS backend found (say / espeak-ng / espeak / piper)" >&2
        echo "  install one (linux: 'apt-get install -y espeak-ng') or set OCTRA_TTS" >&2
        exit 3
    fi
fi
echo "render-with-audio: using TTS backend '${TTS}'"

# ---- helpers -------------------------------------------------------------

# Synthesize a single cue's text to a .wav file. Stays neutral: each
# backend writes WAV (or aiff which ffmpeg can decode); the caller does
# not care about format.
synth_cue() {
    local text="$1"
    local out="$2"
    case "${TTS}" in
        say)
            # 175 wpm is the default; -r 180 is comfortable for tech narration.
            /usr/bin/say -r 180 -o "${out}.aiff" -- "${text}"
            ffmpeg -y -loglevel error -i "${out}.aiff" -ar 44100 -ac 1 "${out}" < /dev/null
            rm -f "${out}.aiff"
            ;;
        espeak-ng|espeak)
            "${TTS}" -s 175 -v en-us -w "${out}" -- "${text}"
            ;;
        piper)
            # piper expects text on stdin + a --model path.
            : "${PIPER_MODEL:?set PIPER_MODEL=/path/to/voice.onnx}"
            printf '%s' "${text}" | piper --model "${PIPER_MODEL}" --output_file "${out}"
            ;;
        *)
            echo "render-with-audio: unknown TTS backend '${TTS}'" >&2
            return 1
            ;;
    esac
}

# Emit one (start_seconds<TAB>text) line per cue from a .vtt file.
parse_vtt() {
    local vtt="$1"
    python3 - "$vtt" <<'PY'
import re, sys, pathlib
text = pathlib.Path(sys.argv[1]).read_text()
ts = r'(\d+):(\d+):(\d+)\.(\d+)'
pat = re.compile(rf'^{ts}\s*-->\s*{ts}\s*$', re.M)
lines = text.splitlines()
i = 0
while i < len(lines):
    m = pat.match(lines[i])
    if m:
        h, mn, s, ms = map(int, m.groups()[:4])
        start = h * 3600 + mn * 60 + s + ms / 1000.0
        # next non-empty line is the cue body
        body = ''
        j = i + 1
        while j < len(lines) and lines[j].strip():
            body += (' ' if body else '') + lines[j].strip()
            j += 1
        # strip a "narrator: " prefix so TTS doesn't read it literally.
        body = re.sub(r'^narrator:\s*', '', body, flags=re.I)
        print(f'{start:.3f}\t{body}')
        i = j
    else:
        i += 1
PY
}

# ---- per-tape pipeline ---------------------------------------------------

ok=0
skipped=0
failed=0
total=0
shopt -s nullglob

for tape in "${TAPES_DIR}"/*.tape; do
    base="$(basename "${tape}" .tape)"
    if [[ -n "${FILTER}" && "${base}" != *"${FILTER}"* ]]; then
        continue
    fi
    total=$((total + 1))

    mp4="${RECORDINGS_DIR}/${base}.mp4"
    vtt="${RECORDINGS_DIR}/${base}.vtt"
    captioned="${RECORDINGS_DIR}/${base}-captioned.mp4"

    if [[ ! -f "${mp4}" ]] || [[ ! -f "${vtt}" ]]; then
        echo "skip ${base}: missing .mp4 or .vtt"
        skipped=$((skipped + 1))
        continue
    fi

    # If a captioned variant already exists, prefer it as the source so
    # the final file carries subtitles + audio together.
    if [[ -f "${captioned}" ]]; then
        src="${captioned}"
        out="${RECORDINGS_DIR}/${base}-narrated-captioned.mp4"
    else
        src="${mp4}"
        out="${RECORDINGS_DIR}/${base}-narrated.mp4"
    fi

    echo "=== ${base} ==="
    scratch="$(mktemp -d)"
    trap 'rm -rf "${scratch}"' EXIT

    # Generate one wav per cue + collect (start, file) tuples.
    idx=0
    > "${scratch}/cues.tsv"
    while IFS=$'\t' read -r start body; do
        [[ -z "${body}" ]] && continue
        cue_wav="${scratch}/cue-$(printf '%03d' "${idx}").wav"
        if synth_cue "${body}" "${cue_wav}" 2>/dev/null; then
            echo -e "${start}\t${cue_wav}" >> "${scratch}/cues.tsv"
        else
            echo "  warn: synth failed for cue ${idx} of ${base}" >&2
        fi
        idx=$((idx + 1))
    done < <(parse_vtt "${vtt}")

    n_cues=$(wc -l < "${scratch}/cues.tsv" | tr -d ' ')
    if [[ "${n_cues}" -eq 0 ]]; then
        echo "  ! no cue audio synthesized for ${base}" >&2
        failed=$((failed + 1))
        rm -rf "${scratch}"
        continue
    fi

    # Probe source duration so we can trim the assembled audio.
    duration="$(ffprobe -v error -show_entries format=duration \
                        -of default=noprint_wrappers=1:nokey=1 "${src}")"

    # Build ffmpeg input list + filter graph.
    #   -i cue0.wav -i cue1.wav ...
    #   [0:a]adelay=START0|START0[a0]; [1:a]adelay=...; amix=n=N
    inputs=()
    filters=()
    labels=""
    i=0
    while IFS=$'\t' read -r start cue_wav; do
        inputs+=(-i "${cue_wav}")
        ms=$(python3 -c "import sys; print(int(round(float(sys.argv[1])*1000)))" "${start}")
        filters+=("[$i:a]adelay=${ms}|${ms},apad[a$i]")
        labels+="[a$i]"
        i=$((i + 1))
    done < "${scratch}/cues.tsv"
    filters+=("${labels}amix=inputs=${n_cues}:normalize=0:dropout_transition=0[mix]")
    filters+=("[mix]atrim=duration=${duration},aresample=44100[aout]")
    filter_graph="$(IFS=';'; echo "${filters[*]}")"

    voiceover="${scratch}/voiceover.wav"
    if ! ffmpeg -y -loglevel error \
            "${inputs[@]}" \
            -filter_complex "${filter_graph}" \
            -map "[aout]" -ac 1 -ar 44100 \
            "${voiceover}" < /dev/null; then
        echo "  ! ffmpeg voiceover assembly failed for ${base}" >&2
        failed=$((failed + 1))
        rm -rf "${scratch}"
        continue
    fi

    # Mux the voiceover onto the source video. Re-encode audio to AAC
    # (mp4 container), copy video stream, preserve subtitle track if any.
    if ! ffmpeg -y -loglevel error \
            -i "${src}" \
            -i "${voiceover}" \
            -map "0:v" -map "1:a" -map "0:s?" \
            -c:v copy -c:a aac -b:a 128k -c:s copy \
            -shortest \
            "${out}" < /dev/null; then
        echo "  ! ffmpeg mux failed for ${base}" >&2
        failed=$((failed + 1))
        rm -rf "${scratch}"
        continue
    fi

    echo "  -> ${out}"
    ok=$((ok + 1))
    rm -rf "${scratch}"
done

echo
echo "render-with-audio: total=${total} ok=${ok} skipped=${skipped} failed=${failed}"
[[ ${failed} -gt 0 ]] && exit 1
exit 0
