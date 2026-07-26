#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
merger="$repo_root/scripts/merge-simulation-coverage-history.sh"
selector="$repo_root/scripts/select-simulation-gaps.sh"

for script in "$merger" "$selector"; do
  if [[ ! -x "$script" ]]; then
    printf 'simulation coverage tool is missing or not executable: %s\n' "$script" >&2
    exit 1
  fi
  bash -n "$script"
done

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
history_root="$fixture_root/history"
mkdir -p "$history_root"

write_aggregate() {
  local output=$1
  local run_id=$2
  local observed_at=$3
  local policy_digest=$4
  local seed_start=$5
  local observed_option=$6
  local missing_first=$7
  local missing_second=$8

  jq -n \
    --argjson run_id "$run_id" \
    --argjson observed_at "$observed_at" \
    --arg policy_digest "$policy_digest" \
    --argjson seed_start "$seed_start" \
    --arg observed_option "$observed_option" \
    --arg missing_first "$missing_first" \
    --arg missing_second "$missing_second" \
    '{
      schema_version: 1,
      source_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      workflow_run_id: $run_id,
      observed_at_unix_secs: $observed_at,
      status: "success",
      coverage: {
        schema_version: 2,
        policy_id: "iroh-network-modes-v1",
        policy_blake3: $policy_digest,
        rolling_window_days: 7,
        completed_runs: 1,
        observed_individuals: [{
          bucket: {
            domain: "direct",
            provider: "deterministic_test",
            choice_id: "latency",
            option_id: $observed_option
          },
          occurrences: 1
        }],
        missing_individuals: [
          {
            domain: "direct",
            provider: "deterministic_test",
            choice_id: "latency",
            option_id: $missing_first
          },
          {
            domain: "direct",
            provider: "deterministic_test",
            choice_id: "latency",
            option_id: $missing_second
          }
        ],
        observed_pairs: [],
        missing_pairs: [{
          first: {
            domain: "direct",
            provider: "production_provider",
            choice_id: "latency",
            option_id: "slow"
          },
          second: {
            domain: "direct",
            provider: "production_provider",
            choice_id: "mtu",
            option_id: "minimum"
          }
        }],
        observed_higher_order: [],
        missing_higher_order: [],
        observed_transitions: [],
        missing_transitions: [{
          domain: "direct",
          provider: "production_provider",
          transition: {
            subject: "path",
            from: "relay",
            to: "direct"
          }
        }],
        observed_oracles: [],
        missing_oracles: [],
        observed_phases: [],
        missing_phases: [],
        known_gaps: [{
          id: "impairment-jitter",
          dimension: "impairment",
          reason: "not modeled"
        }]
      },
      seed_leases: [{
        schema_version: 2,
        policy_blake3: $policy_digest,
        plan_blake3: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        lane_id: "direct/deterministic-test",
        seed_window: $run_id,
        epoch: 0,
        lane_index: 0,
        seed_start: $seed_start,
        seed_end_exclusive: ($seed_start + 1000000),
        consumed_runs: 1
      }],
      unique_failures: [],
      infrastructure_errors: []
    }' >"$output"
}

policy_digest=03cedfb477850423191b22663090d6d49bc8a4276b56c16ec018c6567e36a9a0
write_aggregate "$fixture_root/current.json" 300 200000 "$policy_digest" 300000000 fast slow minimum
write_aggregate "$history_root/previous.json" 299 150000 "$policy_digest" 299000000 slow fast minimum
write_aggregate \
  "$history_root/old-policy.json" \
  298 \
  140000 \
  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  298000000 \
  fast \
  slow \
  minimum

rolling="$fixture_root/rolling.json"
"$merger" \
  --current "$fixture_root/current.json" \
  --history "$history_root" \
  --window-end-unix-secs 200000 \
  --output "$rolling"

jq -e '
  .schema_version == 1
  and .status == "coverage_gaps"
  and .policy_id == "iroh-network-modes-v1"
  and .included_runs == [299, 300]
  and (.excluded_reports | any(.reason == "policy_revision_mismatch"))
  and .coverage.completed_runs == 2
  and (.coverage.observed_individuals | length) == 2
  and (.coverage.missing_individuals | length) == 1
  and .coverage.missing_individuals[0].option_id == "minimum"
  and (.coverage.missing_pairs | length) == 1
  and (.coverage.missing_transitions | length) == 1
  and (.gaps | any(.class == "transition" and .bucket.domain == "direct"))
  and (.gaps | any(.class == "known_unsupported" and .id == "impairment-jitter"))
  and (.gaps | any(.class == "individual" and .reason == "not_observed_in_rolling_window"))
  and (.seed_leases | length) == 2
  and (.infrastructure_errors | length) == 0
' "$rolling" >/dev/null

selection="$fixture_root/gap-selection.json"
"$selector" \
  --rolling "$rolling" \
  --plan "$repo_root/iroh-sim/soaks/daily.json" \
  --max-lanes 4 \
  --output "$selection"

jq -e '
  .schema_version == 1
  and .policy_blake3 == "03cedfb477850423191b22663090d6d49bc8a4276b56c16ec018c6567e36a9a0"
  and .maximum_lanes == 4
  and (.lanes | map(.lane)) == [
    "direct/deterministic-test",
    "direct/production-provider"
  ]
  and (.lanes
    | any(.lane == "direct/production-provider" and (.gap_classes | contains(["transition"]))))
  and (.unassigned_gaps | any(.class == "known_unsupported"))
' "$selection" >/dev/null

overlap_history="$fixture_root/overlap-history"
mkdir -p "$overlap_history"
write_aggregate \
  "$overlap_history/overlap.json" \
  297 \
  130000 \
  "$policy_digest" \
  300500000 \
  slow \
  fast \
  minimum
overlap_output="$fixture_root/overlap.json"
set +e
"$merger" \
  --current "$fixture_root/current.json" \
  --history "$overlap_history" \
  --window-end-unix-secs 200000 \
  --output "$overlap_output"
overlap_status=$?
set -e
if [[ "$overlap_status" -ne 2 ]]; then
  echo "rolling coverage must reject overlapping seed leases" >&2
  exit 1
fi
jq -e '
  .status == "infrastructure_failure"
  and (.infrastructure_errors | any(contains("overlapping seed leases")))
' "$overlap_output" >/dev/null

duplicate_history="$fixture_root/duplicate-history"
mkdir -p "$duplicate_history"
cp "$history_root/previous.json" "$duplicate_history/first.json"
cp "$history_root/previous.json" "$duplicate_history/second.json"
duplicate_output="$fixture_root/duplicate.json"
set +e
"$merger" \
  --current "$fixture_root/current.json" \
  --history "$duplicate_history" \
  --window-end-unix-secs 200000 \
  --output "$duplicate_output"
duplicate_status=$?
set -e
if [[ "$duplicate_status" -ne 2 ]]; then
  echo "rolling coverage must reject duplicate workflow reports" >&2
  exit 1
fi
jq -e '
  .status == "infrastructure_failure"
  and (.infrastructure_errors | any(contains("duplicate workflow runs")))
' "$duplicate_output" >/dev/null

complete_current="$fixture_root/complete-current.json"
jq '
  .coverage.missing_individuals = []
  | .coverage.missing_pairs = []
  | .coverage.missing_higher_order = []
  | .coverage.missing_transitions = []
  | .coverage.missing_oracles = []
  | .coverage.missing_phases = []
  | .coverage.known_gaps = []
' "$fixture_root/current.json" >"$complete_current"
empty_history="$fixture_root/empty-history"
mkdir -p "$empty_history"
complete_output="$fixture_root/complete.json"
"$merger" \
  --current "$complete_current" \
  --history "$empty_history" \
  --window-end-unix-secs 200000 \
  --output "$complete_output"
jq -e '.status == "complete" and .gaps == []' "$complete_output" >/dev/null

set +e
"$merger" \
  --current "$fixture_root/current.json" \
  --history "$fixture_root/missing-history" \
  --window-end-unix-secs 200000 \
  --output "$fixture_root/missing-history.json" \
  >/dev/null 2>&1
missing_history_status=$?
set -e
if [[ "$missing_history_status" -eq 0 ]]; then
  echo "rolling coverage must reject a missing history directory" >&2
  exit 1
fi

echo "simulation rolling coverage contract passed"
