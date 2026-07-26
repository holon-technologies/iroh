#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
aggregator="$repo_root/scripts/aggregate-daily-simulation-soak.sh"

if [[ ! -x "$aggregator" ]]; then
  echo "daily simulation aggregate runner is missing or not executable" >&2
  exit 1
fi

bash -n "$aggregator"

expected_lanes=(
  direct/deterministic-test
  direct/production-provider
  discovery/deterministic-test
  discovery/production-provider
  mobility/deterministic-test
  mobility/production-provider
  nat/deterministic-test
  nat/production-provider
  ready-order/deterministic-test
  ready-order/production-provider
  relay/deterministic-test
  relay/production-provider
)

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT

write_report() {
  local root=$1
  local lane=$2
  local seed_window=$3
  local status=$4
  local slug=${lane//\//-}
  local failed_runs=0
  local successful_runs=10

  if [[ "$status" == "simulation_failure" ]]; then
    failed_runs=1
    successful_runs=9
  fi

  mkdir -p "$root/$slug"
  jq -n \
    --arg lane "$lane" \
    --arg status "$status" \
    --argjson seed_window "$seed_window" \
    --argjson failed_runs "$failed_runs" \
    --argjson successful_runs "$successful_runs" \
    '{
      schema_version: 1,
      status: $status,
      lane: $lane,
      seed_window: $seed_window,
      configured_epochs: 8,
      completed_epochs: 8,
      max_runs_per_epoch: 10416,
      configured_max_runs: 83328,
      infrastructure_failures: 0,
      simulation_failed_epochs: $failed_runs,
      totals: {
        completed_runs: 10,
        successful_runs: $successful_runs,
        failed_runs: $failed_runs,
        errored_runs: 0,
        worker_panics: 0,
        retained_failure_artifacts: $failed_runs,
        omitted_failure_artifacts: 0,
        retained_failure_artifact_bytes: (128 * $failed_runs)
      },
      unique_failures: (
        if $failed_runs == 0 then []
        else [{
          signature: {kind: "invariant", invariant: "fixture"},
          first_lane_id: $lane,
          first_seed: $seed_window,
          occurrences: 1,
          epoch: 0
        }]
        end
      ),
      epochs: [
        range(0; 8) as $epoch
        | {
            epoch: $epoch,
            exit_code: (
              if $epoch == 0 and $failed_runs > 0 then 74 else 0 end
            ),
            summary: {
              plan_id: "daily",
              epoch: $epoch,
              seed_window: $seed_window,
              failure_artifacts: {
                retained: (if $epoch == 0 then $failed_runs else 0 end),
                omitted: 0,
                retained_bytes: (
                  if $epoch == 0 then 128 * $failed_runs else 0 end
                ),
                byte_budget: 33554432,
                artifact_budget: 2,
                infrastructure_error: null
              },
              schema_version: 1,
              config: {
                wall_budget_millis: 1800000,
                jobs: 4,
                batch_runs: 64,
                max_runs: 10416
              },
              stop_reason: "run_budget",
              elapsed_millis: 1,
              completed_runs: (if $epoch == 0 then 10 else 0 end),
              successful_runs: (if $epoch == 0 then $successful_runs else 0 end),
              failed_runs: (if $epoch == 0 then $failed_runs else 0 end),
              errored_runs: 0,
              worker_panics: 0,
              lanes: [{
                id: $lane,
                next_seed: ($seed_window + $epoch),
                completed_runs: (if $epoch == 0 then 10 else 0 end),
                successful_runs: (if $epoch == 0 then $successful_runs else 0 end),
                failed_runs: (if $epoch == 0 then $failed_runs else 0 end),
                errored_runs: 0,
                worker_panics: 0
              }],
              unique_failures: (
                if $epoch == 0 and $failed_runs > 0 then [{
                  signature: {kind: "invariant", invariant: "fixture"},
                  first_lane_id: $lane,
                  first_seed: $seed_window,
                  occurrences: 1
                }]
                else []
                end
              )
            }
          }
      ]
    }' >"$root/$slug/daily-soak-summary.json"
}

success_root="$fixture_root/success"
for lane_index in "${!expected_lanes[@]}"; do
  write_report "$success_root" "${expected_lanes[$lane_index]}" "$((1000 + lane_index))" success
done

success_output="$fixture_root/success-aggregate.json"
"$aggregator" --artifacts "$success_root" --output "$success_output"
jq -e '
  .schema_version == 1
  and .status == "success"
  and .expected_lanes == 12
  and .completed_lanes == 12
  and .received_reports == 12
  and .configured_max_runs == 999936
  and .totals.completed_runs == 120
  and .totals.successful_runs == 120
  and .totals.failed_runs == 0
  and (.unique_failures | length) == 0
  and (.lanes | length) == 12
  and (.infrastructure_errors | length) == 0
' "$success_output" >/dev/null

failure_root="$fixture_root/failure"
for lane_index in "${!expected_lanes[@]}"; do
  status=success
  if ((lane_index < 2)); then
    status=simulation_failure
  fi
  write_report "$failure_root" "${expected_lanes[$lane_index]}" "$((2000 + lane_index))" "$status"
done

failure_output="$fixture_root/failure-aggregate.json"
set +e
"$aggregator" --artifacts "$failure_root" --output "$failure_output"
failure_status=$?
set -e
if [[ "$failure_status" -ne 1 ]]; then
  echo "aggregate runner must propagate valid lane simulation failures" >&2
  exit 1
fi
jq -e '
  .status == "simulation_failure"
  and .totals.failed_runs == 2
  and (.unique_failures | length) == 1
  and .unique_failures[0].occurrences == 2
  and (.unique_failures[0].lanes | length) == 2
' "$failure_output" >/dev/null

missing_root="$fixture_root/missing"
for ((lane_index = 0; lane_index < 11; lane_index++)); do
  write_report "$missing_root" "${expected_lanes[$lane_index]}" "$((3000 + lane_index))" success
done

missing_output="$fixture_root/missing-aggregate.json"
set +e
"$aggregator" --artifacts "$missing_root" --output "$missing_output"
missing_status=$?
set -e
if [[ "$missing_status" -ne 2 ]]; then
  echo "aggregate runner must fail closed when lane evidence is missing" >&2
  exit 1
fi
jq -e '
  .status == "infrastructure_failure"
  and .completed_lanes == 11
  and (.infrastructure_errors | any(contains("missing lanes")))
' "$missing_output" >/dev/null

malformed_root="$fixture_root/malformed"
for lane_index in "${!expected_lanes[@]}"; do
  write_report "$malformed_root" "${expected_lanes[$lane_index]}" "$((4000 + lane_index))" success
done
malformed_report="$malformed_root/direct-deterministic-test/daily-soak-summary.json"
jq '.totals.completed_runs = 11' "$malformed_report" >"$malformed_report.tmp"
mv "$malformed_report.tmp" "$malformed_report"

malformed_output="$fixture_root/malformed-aggregate.json"
set +e
"$aggregator" --artifacts "$malformed_root" --output "$malformed_output"
malformed_status=$?
set -e
if [[ "$malformed_status" -ne 2 ]]; then
  echo "aggregate runner must reject internally inconsistent lane reports" >&2
  exit 1
fi
jq -e '
  .status == "infrastructure_failure"
  and (.infrastructure_errors | any(contains("malformed lane report")))
' "$malformed_output" >/dev/null

underconfigured_root="$fixture_root/underconfigured"
for lane_index in "${!expected_lanes[@]}"; do
  lane=${expected_lanes[$lane_index]}
  write_report "$underconfigured_root" "$lane" "$((5000 + lane_index))" success
  slug=${lane//\//-}
  report="$underconfigured_root/$slug/daily-soak-summary.json"
  jq '
    .configured_epochs = 1
    | .completed_epochs = 1
    | .max_runs_per_epoch = 100
    | .configured_max_runs = 100
    | .epochs = [.epochs[0]]
  ' "$report" >"$report.tmp"
  mv "$report.tmp" "$report"
done

underconfigured_output="$fixture_root/underconfigured-aggregate.json"
set +e
"$aggregator" --artifacts "$underconfigured_root" --output "$underconfigured_output"
underconfigured_status=$?
set -e
if [[ "$underconfigured_status" -ne 2 ]]; then
  echo "aggregate runner must reject evidence below the production configuration" >&2
  exit 1
fi

duplicate_seed_root="$fixture_root/duplicate-seed"
for lane_index in "${!expected_lanes[@]}"; do
  seed_window=$((6000 + lane_index))
  if ((lane_index == 1)); then
    seed_window=6000
  fi
  write_report \
    "$duplicate_seed_root" \
    "${expected_lanes[$lane_index]}" \
    "$seed_window" \
    success
done

duplicate_seed_output="$fixture_root/duplicate-seed-aggregate.json"
set +e
"$aggregator" --artifacts "$duplicate_seed_root" --output "$duplicate_seed_output"
duplicate_seed_status=$?
set -e
if [[ "$duplicate_seed_status" -ne 2 ]]; then
  echo "aggregate runner must reject duplicate lane seed windows" >&2
  exit 1
fi
jq -e '
  .status == "infrastructure_failure"
  and (.infrastructure_errors | any(contains("duplicate seed windows")))
' "$duplicate_seed_output" >/dev/null

echo "daily simulation aggregate contract passed"
