#!/usr/bin/env bash
# bench-regression.sh — compare a fresh octravpn-core bench run against
# the committed snapshot at bench-snapshots/core.json.
#
# Exit codes:
#   0  — all benches within tolerance (default 20% slower)
#   1  — at least one bench regressed past the threshold
#   2  — environment problem (missing jq, criterion output not found, etc.)
#
# Regenerating the snapshot intentionally (e.g. after a perf-changing PR):
#   1. Run with the same args the committed snapshot used so estimates
#      stay comparable:
#         cargo bench -p octravpn-core --bench core -- \
#             --sample-size 20 --warm-up-time 1 --measurement-time 2
#   2. Collect the per-bench estimates from
#         target/criterion/<bench_id>/new/estimates.json
#      Each file exposes `mean.point_estimate`, `mean.confidence_interval.{lower,upper}_bound`.
#   3. Rewrite bench-snapshots/core.json with the new numbers and the host
#      metadata block (arch, cpu, os version, criterion_args, run_at_utc).
#      The exact shape is verified by this script — see KEYS below.
#
# This script can also be sourced as the lone bench gate (the CI job
# `bench-regression` does exactly that). It runs the criterion harness
# in the same configuration the snapshot was captured with so the
# comparison is apples-to-apples; on a noisy CI runner the 20% gate is
# the empirical floor that doesn't false-positive.

set -euo pipefail

cd "$(dirname "$0")/.."

SNAPSHOT="bench-snapshots/core.json"
THRESHOLD_PCT="${BENCH_REGRESSION_PCT:-20}"
# Optional: speed knob. When BENCH_REGRESSION_QUICK=1 we shorten
# criterion's measurement to keep CI under a few minutes; the
# comparison still uses the committed mean, so a noisy short run only
# affects sensitivity, not correctness.
QUICK="${BENCH_REGRESSION_QUICK:-0}"

if ! command -v jq >/dev/null 2>&1; then
  echo "bench-regression: jq is required" >&2
  exit 2
fi

if [[ ! -f "$SNAPSHOT" ]]; then
  echo "bench-regression: snapshot not found at $SNAPSHOT" >&2
  exit 2
fi

# Read committed args so a fresh run uses the same shape. Fall back to
# a sensible default if the snapshot somehow lacks the field.
SNAPSHOT_ARGS="$(jq -r '.criterion_args // "--sample-size 20 --warm-up-time 1 --measurement-time 2"' "$SNAPSHOT")"
if [[ "$QUICK" == "1" ]]; then
  SNAPSHOT_ARGS="--sample-size 10 --warm-up-time 1 --measurement-time 1"
fi

echo "bench-regression: running cargo bench -p octravpn-core --bench core -- $SNAPSHOT_ARGS"
# Criterion writes target/criterion/<bench_id>/new/estimates.json on
# every run. We blow away the directory first so a stale run from a
# prior commit doesn't leak in.
rm -rf target/criterion
# shellcheck disable=SC2086
cargo bench -p octravpn-core --bench core -- $SNAPSHOT_ARGS

BENCHES_JSON="$(jq -r '.benchmarks | keys[]' "$SNAPSHOT")"

regressed=0
faster=0
missing=0

printf '\n%-30s %12s %12s %8s  %s\n' "bench" "snapshot ns" "fresh ns" "delta%" "status"
printf -- '------------------------------------------------------------------------------------\n'

while IFS= read -r bench; do
  est="target/criterion/${bench}/new/estimates.json"
  if [[ ! -f "$est" ]]; then
    printf '%-30s %12s %12s %8s  %s\n' "$bench" "-" "-" "-" "MISSING (criterion did not emit)"
    missing=$((missing + 1))
    continue
  fi
  snap_mean="$(jq -r --arg b "$bench" '.benchmarks[$b].mean_ns' "$SNAPSHOT")"
  new_mean="$(jq -r '.mean.point_estimate' "$est")"
  delta_pct="$(awk -v s="$snap_mean" -v n="$new_mean" 'BEGIN { if (s+0 == 0) print 0; else printf "%.1f", ((n - s) / s) * 100 }')"

  status="ok"
  exceeded="$(awk -v d="$delta_pct" -v t="$THRESHOLD_PCT" 'BEGIN { print (d > t) ? 1 : 0 }')"
  improved="$(awk -v d="$delta_pct" -v t="$THRESHOLD_PCT" 'BEGIN { print (-d > t) ? 1 : 0 }')"
  if [[ "$exceeded" == "1" ]]; then
    status="REGRESSED (>${THRESHOLD_PCT}% slower)"
    regressed=$((regressed + 1))
  elif [[ "$improved" == "1" ]]; then
    status="faster (>${THRESHOLD_PCT}% improvement — snapshot may be stale)"
    faster=$((faster + 1))
  fi
  printf '%-30s %12.2f %12.2f %+8s  %s\n' "$bench" "$snap_mean" "$new_mean" "${delta_pct}%" "$status"
done <<< "$BENCHES_JSON"

# Surface any new benches present on disk but absent from the snapshot.
# Per spec these are warnings, not failures.
if [[ -d target/criterion ]]; then
  while IFS= read -r dir; do
    name="$(basename "$dir")"
    if ! jq -e --arg b "$name" '.benchmarks[$b]' "$SNAPSHOT" >/dev/null 2>&1; then
      # Skip the criterion 'report' meta-directory.
      [[ "$name" == "report" ]] && continue
      printf '%-30s %12s %12s %8s  %s\n' "$name" "-" "$(jq -r '.mean.point_estimate' "$dir/new/estimates.json" 2>/dev/null || echo '?')" "-" "NEW (not in snapshot — warn only)"
    fi
  done < <(find target/criterion -mindepth 1 -maxdepth 1 -type d)
fi

echo
if [[ "$regressed" -gt 0 ]]; then
  echo "bench-regression: FAIL — ${regressed} bench(es) slower than snapshot by >${THRESHOLD_PCT}%"
  exit 1
fi
if [[ "$faster" -gt 0 ]]; then
  echo "bench-regression: PASS, but ${faster} bench(es) ran >${THRESHOLD_PCT}% faster than snapshot."
  echo "                  Consider refreshing bench-snapshots/core.json — see top of this script."
fi
if [[ "$missing" -gt 0 ]]; then
  echo "bench-regression: PASS, but ${missing} snapshot bench(es) had no criterion output."
fi
echo "bench-regression: PASS"
exit 0
