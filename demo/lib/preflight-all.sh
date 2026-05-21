#!/usr/bin/env bash
# preflight-all.sh
#
# Orchestrator that runs `demo/lib/preflight-tape.sh` against every
# realized tape that's expected to PASS, then prints a per-tape
# verdict table.  CI gates the nightly demo job on this (the demo
# workflow's vhs step skips when its preflight failed).
#
# Tapes intentionally NOT run:
#   05  — delegates to docker/devnet/v3-smoke.sh (which exit-codes on its own)
#   06  — delegates to docker/devnet/tailscale-interop/run-interop.sh
#   11  — OS-install fake (commented brew/apt steps; nothing to exec)
#   12  — OS-install fake (commented brew/apt steps; nothing to exec)
#
# Usage:
#   bash demo/lib/preflight-all.sh
#
# Exit:
#   0  every preflighted tape PASSED
#   1  one or more tapes FAILED

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
PREFLIGHT="${SCRIPT_DIR}/preflight-tape.sh"

# Share the bringup-idempotency cache across all tapes so adjacent
# tapes that re-use a harness (3node-mesh-bringup is in 04/07/08/09/10/13/14/18/22)
# pay only one bringup cost per `preflight-all` invocation.
export PREFLIGHT_CACHE_DIR="${PREFLIGHT_CACHE_DIR:-/tmp/octravpn-demo-preflight-all-$$}"
mkdir -p "${PREFLIGHT_CACHE_DIR}"

# Tape harness groupings — each group shares a bringup.  We process
# tapes in group order so a teardown only happens when we cross a
# group boundary.
declare -A TAPE_HARNESS=(
    ["01"]="keygen-fixture"
    ["02"]="portal-container"
    ["03"]="audit-fixture"
    ["04"]="3node-mesh"
    ["07"]="3node-mesh"
    ["08"]="3node-mesh"
    ["09"]="3node-mesh"
    ["10"]="3node-mesh"
    ["13"]="3node-mesh"
    ["14"]="3node-mesh"
    ["15"]="portal-container"
    ["16"]="portal-container"
    ["17"]="devnet-mock"
    ["18"]="3node-mesh"
    ["19"]="devnet-mock"
    ["20"]="pvac"
    ["21"]="audit-fixture"
    ["22"]="3node-mesh"
)

# Order chosen to cluster shared harnesses (avoid teardown thrash).
ORDER=(01 02 15 16 03 21 17 19 04 07 08 09 10 13 14 18 22 20 00)

# Skipped tapes.
SKIPS=(05 06 11 12)

is_skipped() {
    local id="$1"
    for s in "${SKIPS[@]}"; do
        [[ "${s}" == "${id}" ]] && return 0
    done
    return 1
}

teardown_harness() {
    local harness="$1"
    local script="${SCRIPT_DIR}/${harness}-teardown.sh"
    if [[ -x "${script}" ]]; then
        echo ">>> teardown ${harness}" >&2
        bash "${script}" >/dev/null 2>&1 || true
    fi
    # Also flush this harness's bringup-cache key so the NEXT group
    # using a sibling harness re-runs its bringup.
    rm -f "${PREFLIGHT_CACHE_DIR}/_demo_lib_${harness}-bringup.sh.done" 2>/dev/null || true
}

declare -A RESULT
declare -A LOG_PATH
prev_harness=""

# Master-tour tape 00 uses every harness sequentially — run it
# stand-alone at the END so a failure there doesn't poison earlier
# tape verdicts.

run_one() {
    local id="$1"
    local tape
    tape=$(ls "${REPO_ROOT}/demo/tapes/${id}-"*.tape 2>/dev/null | head -1)
    if [[ -z "${tape}" ]]; then
        echo "no tape matching ${id}-*.tape" >&2
        return 0
    fi
    local harness="${TAPE_HARNESS[${id}]:-}"
    if [[ -n "${prev_harness}" && "${harness}" != "${prev_harness}" && "${prev_harness}" != "shared" ]]; then
        teardown_harness "${prev_harness}"
    fi
    local log="${PREFLIGHT_CACHE_DIR}/${id}.log"
    LOG_PATH[${id}]="${log}"
    echo "============================================================" >&2
    echo "=== Tape ${id}  (harness: ${harness:-(none)})" >&2
    echo "============================================================" >&2
    if bash "${PREFLIGHT}" "${tape}" 2>&1 | tee "${log}" \
        | tail -2 | head -1 | grep -q "0 FAIL"; then
        RESULT[${id}]=PASS
    else
        RESULT[${id}]=FAIL
    fi
    prev_harness="${harness}"
}

for id in "${ORDER[@]}"; do
    if is_skipped "${id}"; then continue; fi
    run_one "${id}"
done

# Final teardown.
if [[ -n "${prev_harness}" ]]; then
    teardown_harness "${prev_harness}"
fi

# ----- summary -----------------------------------------------------------

echo ""
echo "============================================================"
echo "PREFLIGHT SUMMARY"
echo "============================================================"
printf '%-6s %-20s %-8s %s\n' "TAPE" "HARNESS" "VERDICT" "LAST-LINE"
overall=0
for id in 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22; do
    if is_skipped "${id}"; then
        printf '%-6s %-20s %-8s %s\n' "${id}" "(n/a)" "SKIP" "delegated / fake"
        continue
    fi
    verdict="${RESULT[${id}]:-MISSING}"
    last=""
    if [[ -n "${LOG_PATH[${id}]:-}" && -f "${LOG_PATH[${id}]}" ]]; then
        last=$(grep -E '^PREFLIGHT:' "${LOG_PATH[${id}]}" | tail -1)
    fi
    printf '%-6s %-20s %-8s %s\n' "${id}" "${TAPE_HARNESS[${id}]:-}" "${verdict}" "${last}"
    if [[ "${verdict}" == FAIL ]]; then overall=1; fi
done

if (( overall == 0 )); then
    echo ""
    echo "OVERALL: PASS"
    exit 0
fi
echo ""
echo "OVERALL: FAIL — see per-tape logs under ${PREFLIGHT_CACHE_DIR}/"
exit 1
