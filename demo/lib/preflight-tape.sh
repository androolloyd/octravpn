#!/usr/bin/env bash
# preflight-tape.sh
#
# Validate every command in a vhs tape returns exit 0 against the
# live docker harness BEFORE `vhs` records.  Prevents shipping
# error output as "the demo" (the failure mode codified in
# `memory/demo_preflight_required.md`).
#
# Usage:
#   bash demo/lib/preflight-tape.sh demo/tapes/04-mesh-preauth.tape
#
# Exit:
#   0  every command in the tape returned exit 0
#   1  at least one command failed (per-command verdict on stderr)
#   2  invocation error (tape missing, etc.)
#
# Heuristics (deliberately conservative — we'd rather skip a line and
# let the rendered tape catch a bug than execute non-command JSON data
# typed into a `cat > /tmp/foo.json` heredoc):
#
#   * `Type "<text>"`  and  `Type \`<text>\``  are extracted; the
#     surrounding quote / backtick is stripped, internal escaped
#     quotes are unescaped.
#   * A typed line that starts with `#` (after the quote strip) is
#     pure tape-narration; vhs will type it and Enter is then a
#     no-op shell comment.  Skipped silently.
#   * If the IMMEDIATELY-PRECEDING typed line ends in `cat > <path>`
#     (with optional `sh -c '...'` wrapper) we treat the next typed
#     line as the heredoc payload, write it to the target path via
#     a real `docker exec -i ... sh -c 'cat > <path>'` so subsequent
#     commands see the file, and DO NOT score it as a separate
#     command.
#   * Lines that don't look like a shell command (don't start with
#     a letter, `/`, `.`, `_`, `$`, or `VAR=`) are skipped with a
#     `SKIP-NONCMD` verdict — JSON blobs that escaped the heredoc
#     detector land here.
#   * `bash demo/lib/<bringup>.sh` IS treated as a real command (it
#     IS the runtime-state setup we need) — but we run it through
#     an idempotency cache so re-running the same bringup across
#     multiple tape preflights is cheap.
#
# Output is one line per scored command + a final summary:
#
#   PASS  docker exec mesh-demo-control octravpn-node mesh status ...
#   FAIL  docker exec ... headscale users list (exit 6) — config not found
#   PREFLIGHT: 12/14 PASS, 2 FAIL

set -uo pipefail

TAPE="${1:-}"
if [[ -z "${TAPE}" ]]; then
    echo "usage: $0 <tape.tape>" >&2
    exit 2
fi
if [[ ! -f "${TAPE}" ]]; then
    echo "preflight-tape: tape not found: ${TAPE}" >&2
    exit 2
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

# Idempotency cache for `bash demo/lib/<bringup>.sh` invocations.
# A single preflight-all run may touch a bringup script multiple
# times across sibling tapes that share a harness.  The cache lives
# under /tmp so a fresh shell invocation always re-runs (we don't
# want stale "already up" markers to mask a teardown done by an
# unrelated CI job).
PREFLIGHT_CACHE_DIR="${PREFLIGHT_CACHE_DIR:-/tmp/octravpn-demo-preflight-$$}"
mkdir -p "${PREFLIGHT_CACHE_DIR}"

total=0
passed=0
failed=0

# ----- tape parser -------------------------------------------------------

# Extract typed lines + sleeps in tape order.  Each element is
# one of:
#     CMD:<literal command string>
#     SLEEP:<seconds-as-float>
# so the executor can pause between commands the same way vhs does.
# This matters for tapes that rely on a 1-3s settle between
# starting a server (`docker exec -d ... httpd`) and the first
# client request.
mapfile -t TYPED < <(
    awk '
        # Capture Type "..."  (double-quoted form).
        /^Type "/ {
            line = substr($0, 7)
            line = substr(line, 1, length(line) - 1)
            gsub(/\\"/, "\"", line)
            print "CMD:" line
            next
        }
        # Capture Type `...`  (backtick form).
        /^Type `/ {
            line = substr($0, 7)
            line = substr(line, 1, length(line) - 1)
            print "CMD:" line
            next
        }
        # Capture Sleep <dur>  — convert ms / s to seconds.
        /^Sleep / {
            dur = $2
            n   = dur
            sub(/[a-zA-Z]+$/, "", n)
            unit = dur
            sub(/^[0-9.]+/, "", unit)
            secs = n
            if (unit == "ms") secs = n / 1000.0
            else if (unit == "m") secs = n * 60
            # Clamp: tapes occasionally Sleep 60s+ to let bringups
            # settle; the bringup script itself is synchronous in
            # preflight so we cap the per-sleep at 5s.
            if (secs > 5) secs = 5
            print "SLEEP:" secs
            next
        }
    ' "${TAPE}"
)

# ----- command classifier ------------------------------------------------

# A line is a "real command" if:
#   * it does not start with `#`
#   * it starts with a letter, digit, `/`, `.`, `_`, `$`, or `VAR=`
#     (i.e. it parses as a shell command, not a JSON object)
is_command_line() {
    local line="$1"
    [[ -z "${line}" ]] && return 1
    [[ "${line}" == \#* ]] && return 1
    # Reject obvious JSON / data payloads.
    [[ "${line}" == \{* ]] && return 1
    [[ "${line}" == \[* ]] && return 1
    # Allow:  letter, /, ., _, $, VAR=value, FOO=bar cmd ...
    [[ "${line}" =~ ^([A-Za-z_/.]|[A-Z][A-Z0-9_]*=) ]]
}

# Detect a heredoc opener in the previous line.  If so, the current
# line is the payload, and we need to write it through docker.
# Returns 0 + sets HEREDOC_TARGET_CMD if a heredoc was detected.
HEREDOC_TARGET_CMD=""
detect_heredoc_opener() {
    local prev="$1"
    HEREDOC_TARGET_CMD=""
    # Match patterns like:
    #   docker exec -i <c> sh -c 'cat > /tmp/foo.json'
    #   docker compose ... exec -iT <svc> sh -c 'cat > /tmp/foo.json'
    #   docker compose -f a.yml -f b.yml exec -iT <svc> sh -c 'cat > /tmp/foo.json'
    # The classic regex only allowed one `-f` flag; demo flows that
    # overlay a second compose file (e.g. docker-compose.demo.yml)
    # need to be recognized too. Permissive: any prefix that contains
    # `docker` and ends with `... sh -c 'cat > <path>'` qualifies.
    if [[ "${prev}" =~ docker[[:space:]] && \
          "${prev}" =~ sh[[:space:]]+-c[[:space:]]+\'cat[[:space:]]+\>[[:space:]]+[^\']+\' ]]; then
        HEREDOC_TARGET_CMD="${prev}"
        return 0
    fi
    return 1
}

# ----- executor ----------------------------------------------------------
#
# vhs replays the tape into a SINGLE persistent terminal — env vars
# assigned by `PEER2_IP=$(docker exec ...)` survive to the next Type
# line.  We mirror that by driving one long-lived `bash` subshell
# through coprocs (every command goes through the same shell, in
# order), reading exit codes via a sentinel.

PREFLIGHT_SHELL_IN="${PREFLIGHT_CACHE_DIR}/shell.in"
PREFLIGHT_SHELL_OUT="${PREFLIGHT_CACHE_DIR}/shell.out"
PREFLIGHT_SHELL_ERR="${PREFLIGHT_CACHE_DIR}/shell.err"
PREFLIGHT_SHELL_PID=""

start_persistent_shell() {
    # Already running?
    if [[ -n "${PREFLIGHT_SHELL_PID}" ]] && kill -0 "${PREFLIGHT_SHELL_PID}" 2>/dev/null; then
        return
    fi
    rm -f "${PREFLIGHT_SHELL_IN}" "${PREFLIGHT_SHELL_OUT}" "${PREFLIGHT_SHELL_ERR}"
    mkfifo "${PREFLIGHT_SHELL_IN}" || true
    # Keep the FIFO open from this process so the shell doesn't EOF.
    exec 9<>"${PREFLIGHT_SHELL_IN}"
    bash >"${PREFLIGHT_SHELL_OUT}" 2>"${PREFLIGHT_SHELL_ERR}" <"${PREFLIGHT_SHELL_IN}" &
    PREFLIGHT_SHELL_PID=$!
    # Pin the persistent shell's cwd to the repo root so tape commands
    # that reference relative paths (`docker-compose.yml`, etc.) resolve
    # correctly regardless of where preflight-tape.sh was invoked from.
    printf 'cd %q\n' "${REPO_ROOT}" >&9
}

stop_persistent_shell() {
    if [[ -n "${PREFLIGHT_SHELL_PID}" ]]; then
        echo 'exit' >&9 2>/dev/null || true
        exec 9>&- 2>/dev/null || true
        wait "${PREFLIGHT_SHELL_PID}" 2>/dev/null || true
        PREFLIGHT_SHELL_PID=""
    fi
}

trap stop_persistent_shell EXIT

# Run one tape command through the persistent shell.  Returns the
# exit code via a sentinel marker we grep out of the captured stderr.
run_cmd_persistent() {
    local cmd="$1"
    start_persistent_shell
    # Truncate stdout/stderr for this command so we can scope output
    # to this line only.
    : > "${PREFLIGHT_SHELL_OUT}"
    : > "${PREFLIGHT_SHELL_ERR}"
    local sentinel="__PREFLIGHT_DONE_${RANDOM}_${RANDOM}__"
    # Send the command (wrapped in a `timeout` so a hung command
    # can't wedge the preflight forever) + a sentinel that echoes
    # $? to stderr.  120s per command is generous — bringups are
    # cached, real CLI invocations finish in seconds.
    local per_cmd_timeout="${PREFLIGHT_CMD_TIMEOUT:-120}"
    # Variable assignments (`FOO=bar`, `FOO=$(cmd)`, possibly chained
    # with `; cmd2`) MUST run directly in the persistent shell so the
    # assignment survives to the next tape line. Wrapping them in
    # `bash -c` would put them in a subshell whose vars are discarded.
    # We detect a leading `IDENT=` assignment at the start of the line
    # (mirroring vhs's `Type "FOO=..."` form used to thread the resolved
    # circle id through subsequent docker exec calls).
    local is_assignment=0
    if [[ "${cmd}" =~ ^[[:space:]]*[A-Za-z_][A-Za-z_0-9]*= ]]; then
        is_assignment=1
    fi
    {
        # Honour any pre-existing `&&`/`||` chain by wrapping in a
        # subshell.  bash 4+ `timeout` isn't a builtin; we use the
        # GNU coreutils binary if present, falling back to a
        # background-PID kill if not (macOS dev hosts have neither
        # `timeout` nor `gtimeout` by default — Docker for Mac
        # includes coreutils though, so most paths are covered).
        if (( is_assignment == 1 )); then
            # Run directly so `FOO=$(...)` persists across commands.
            # Auto-export the leading identifier so subsequent
            # `bash -c "cmd ... $FOO"` invocations (which run in a
            # subshell, see below) inherit the value via the env.
            # Redirect stdin to /dev/null so commands like
            # `docker compose exec -T` don't block on the persistent
            # shell's FIFO stdin.
            local _ident
            _ident=$(printf '%s' "${cmd}" \
                | sed -nE 's/^[[:space:]]*([A-Za-z_][A-Za-z_0-9]*)=.*/\1/p')
            printf '{ %s ; } </dev/null\n' "${cmd}"
            if [[ -n "${_ident}" ]]; then
                printf 'export %s\n' "${_ident}"
            fi
        elif command -v timeout >/dev/null 2>&1; then
            printf 'timeout %ss bash -c %q </dev/null\n' "${per_cmd_timeout}" "${cmd}"
        elif command -v gtimeout >/dev/null 2>&1; then
            printf 'gtimeout %ss bash -c %q </dev/null\n' "${per_cmd_timeout}" "${cmd}"
        else
            printf '{ %s ; } </dev/null\n' "${cmd}"
        fi
        printf 'echo "%s:$?" 1>&2\n' "${sentinel}"
    } >&9
    # Poll the stderr file for the sentinel; bail after 2× per-cmd
    # timeout so a single hung command never wedges the whole tape.
    local deadline=$(( $(date +%s) + per_cmd_timeout * 2 ))
    local code=""
    while (( $(date +%s) < deadline )); do
        if grep -aq "${sentinel}:" "${PREFLIGHT_SHELL_ERR}" 2>/dev/null; then
            code=$(grep -a "${sentinel}:" "${PREFLIGHT_SHELL_ERR}" | tail -1 | sed -E "s/.*${sentinel}:([0-9]+).*/\\1/")
            break
        fi
        sleep 0.2
    done
    if [[ -z "${code}" ]]; then
        printf 'FAIL  %s (preflight-shell timeout)\n' "${cmd}"
        failed=$((failed + 1))
        # The persistent shell is wedged on this hung command; kill +
        # restart so subsequent commands get a fresh shell. Without
        # this, every later command also reports "timeout" because the
        # sentinel from the wedged command never arrives.
        stop_persistent_shell
        return 1
    fi
    # Defensive: if sed didn't yield a pure integer (e.g. grep
    # returned "Binary file matches"), fall back to exit-code 99 so
    # the verdict is FAIL and arithmetic doesn't trip set -u.
    if ! [[ "${code}" =~ ^[0-9]+$ ]]; then
        printf 'FAIL  %s (preflight-shell unparseable exit: %s)\n' "${cmd}" "${code}"
        failed=$((failed + 1))
        return 1
    fi
    if (( code == 0 )); then
        printf 'PASS  %s\n' "${cmd}"
        passed=$((passed + 1))
        return 0
    fi
    local hint
    # Drop the sentinel line itself from the hint.
    hint=$(grep -av "${sentinel}:" "${PREFLIGHT_SHELL_ERR}" 2>/dev/null | tail -n 1 || true)
    printf 'FAIL  %s (exit %s) — %s\n' "${cmd}" "${code}" "${hint:-<no stderr>}"
    failed=$((failed + 1))
    return 1
}

# Standalone runner (used for bringups via a fresh subshell — they
# don't need persistent env, and they're idempotency-cached anyway).
run_cmd() {
    run_cmd_persistent "$1"
}

# bash demo/lib/<name>.sh — cached.
run_bringup() {
    local cmd="$1"
    # Extract the script path; use the path as cache key.
    local script
    script=$(printf '%s\n' "${cmd}" | awk '{for(i=1;i<=NF;i++) if ($i ~ /\.sh$/) {print $i; exit}}')
    if [[ -z "${script}" ]]; then
        run_cmd "${cmd}"
        return $?
    fi
    local cache_key
    cache_key="${PREFLIGHT_CACHE_DIR}/$(printf '%s' "${script}" | tr '/' '_').done"
    if [[ -f "${cache_key}" ]]; then
        printf 'PASS  %s  (cached)\n' "${cmd}"
        total=$((total + 1))
        passed=$((passed + 1))
        return 0
    fi
    total=$((total + 1))
    if run_cmd "${cmd}"; then
        : > "${cache_key}"
        return 0
    fi
    return 1
}

# ----- main loop ---------------------------------------------------------

prev_typed=""
for raw in "${TYPED[@]}"; do
    # SLEEP:<secs> — honor inter-command pauses up to a cap (cap
    # already applied in awk).
    if [[ "${raw}" == SLEEP:* ]]; then
        secs="${raw#SLEEP:}"
        sleep "${secs}" 2>/dev/null || true
        continue
    fi
    # CMD:<line>
    line="${raw#CMD:}"

    # Skip narration: `# anything`
    if [[ "${line}" == \#* ]]; then
        prev_typed="${line}"
        continue
    fi

    # Heredoc payload?  Pipe it through the previous opener.
    if detect_heredoc_opener "${prev_typed}"; then
        if ! is_command_line "${line}"; then
            # Build a one-shot replay of the opener with stdin = the
            # payload.  We embed the payload as a here-string into the
            # persistent shell so subsequent commands see the file.
            # Escape any single-quotes in the payload.
            esc_payload=${line//\'/\'\\\'\'}
            esc_opener=${HEREDOC_TARGET_CMD//\'/\'\\\'\'}
            replay_cmd="printf '%s\\n' '${esc_payload}' | ${HEREDOC_TARGET_CMD}"
            total=$((total + 1))
            if run_cmd_persistent "${replay_cmd}" >/dev/null; then
                # run_cmd_persistent already printed a PASS line.  We
                # overwrite it with a more readable heredoc-payload
                # marker so the scorer output stays compact.
                :
            fi
            # Replace the most-recent verdict line: rewrite it via a
            # second printf so the output reflects the heredoc nature.
            printf '      (heredoc payload → %s)\n' "${HEREDOC_TARGET_CMD}"
            prev_typed="${line}"
            continue
        fi
    fi

    # Non-command (JSON blob without a preceding heredoc opener,
    # `# narration without `#` prefix, etc.)
    if ! is_command_line "${line}"; then
        printf 'SKIP  %s  (not a shell command)\n' "${line}"
        prev_typed="${line}"
        continue
    fi

    # Real command — but is it a bringup?  Cache those.
    if [[ "${line}" == bash\ demo/lib/*-bringup.sh* || "${line}" == bash\ demo/lib/*-teardown.sh* ]]; then
        run_bringup "${line}" || true
        prev_typed="${line}"
        continue
    fi

    total=$((total + 1))
    run_cmd "${line}" || true
    prev_typed="${line}"
done

printf '\nPREFLIGHT: %d/%d PASS, %d FAIL  (%s)\n' \
    "${passed}" "${total}" "${failed}" "$(basename "${TAPE}")"

if (( failed > 0 )); then
    exit 1
fi
exit 0
