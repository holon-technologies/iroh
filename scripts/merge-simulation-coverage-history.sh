#!/usr/bin/env bash

set -euo pipefail

current=
history=
window_end=
output=
maximum_history_reports=32
maximum_report_bytes=16777216
window_seconds=604800

usage() {
  printf '%s\n' \
    'Usage: merge-simulation-coverage-history.sh --current PATH --history PATH --window-end-unix-secs N --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --current)
      current=$2
      shift 2
      ;;
    --history)
      history=$2
      shift 2
      ;;
    --window-end-unix-secs)
      window_end=$2
      shift 2
      ;;
    --output)
      output=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown rolling coverage argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$current" || -z "$history" || -z "$window_end" || -z "$output" ]]; then
  echo '--current, --history, --window-end-unix-secs, and --output are required' >&2
  usage >&2
  exit 64
fi
if [[ ! "$window_end" =~ ^[0-9]+$ ]]; then
  echo '--window-end-unix-secs must be an unsigned decimal integer' >&2
  exit 64
fi
if [[ ! -f "$current" || -L "$current" ]]; then
  printf 'current simulation aggregate is missing or unsafe: %s\n' "$current" >&2
  exit 66
fi
if [[ ! -d "$history" || -L "$history" ]]; then
  printf 'simulation history directory is missing or unsafe: %s\n' "$history" >&2
  exit 66
fi
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
mkdir -p "$(dirname "$output")"

scratch_root=$(mktemp -d)
trap 'rm -rf "$scratch_root"' EXIT
valid_reports="$scratch_root/valid-reports.jsonl"
excluded_reports="$scratch_root/excluded-reports.jsonl"
infrastructure_errors="$scratch_root/infrastructure-errors.jsonl"
: >"$valid_reports"
: >"$excluded_reports"
: >"$infrastructure_errors"

record_excluded() {
  jq -cn --arg path "$1" --arg reason "$2" '{path: $path, reason: $reason}' \
    >>"$excluded_reports"
}

record_infrastructure_error() {
  jq -cn --arg message "$1" '$message' >>"$infrastructure_errors"
}

report_contract='
  def uint: type == "number" and . >= 0 and floor == .;
  def digest: type == "string" and test("^[0-9a-f]{64}$");
  type == "object"
  and .schema_version == 1
  and (.source_revision | type == "string" and test("^[0-9a-f]{40}$"))
  and (.workflow_run_id | uint)
  and (.observed_at_unix_secs | uint)
  and (.coverage | type == "object")
  and .coverage.schema_version == 2
  and (.coverage.policy_id | type == "string" and length > 0 and length <= 128)
  and (.coverage.policy_blake3 | digest)
  and .coverage.rolling_window_days == 7
  and (.coverage.completed_runs | uint)
  and (.coverage.observed_individuals | type == "array")
  and (.coverage.missing_individuals | type == "array")
  and (.coverage.observed_pairs | type == "array")
  and (.coverage.missing_pairs | type == "array")
  and (.coverage.observed_higher_order | type == "array")
  and (.coverage.missing_higher_order | type == "array")
  and (.coverage.observed_transitions | type == "array")
  and (.coverage.missing_transitions | type == "array")
  and (.coverage.observed_oracles | type == "array")
  and (.coverage.missing_oracles | type == "array")
  and (.coverage.observed_phases | type == "array")
  and (.coverage.missing_phases | type == "array")
  and (.coverage.known_gaps | type == "array")
  and (.seed_leases | type == "array" and length > 0 and length <= 384)
  and all(.seed_leases[];
    .schema_version == 2
    and (.policy_blake3 | digest)
    and (.plan_blake3 | digest)
    and (.seed_start | uint)
    and (.seed_end_exclusive | uint)
    and .seed_start < .seed_end_exclusive
    and (.consumed_runs | uint)
    and .consumed_runs <= (.seed_end_exclusive - .seed_start))
'

current_bytes=$(stat -c %s "$current")
if ((current_bytes > maximum_report_bytes)); then
  echo 'current simulation aggregate exceeds the byte bound' >&2
  exit 65
fi
if ! jq -e "$report_contract" "$current" >/dev/null 2>&1; then
  echo 'current simulation aggregate is malformed' >&2
  exit 65
fi

current_policy=$(jq -r '.coverage.policy_blake3' "$current")
current_plan=$(jq -r '.seed_leases[0].plan_blake3' "$current")
window_start=$((window_end > window_seconds ? window_end - window_seconds : 0))
jq -c . "$current" >>"$valid_reports"

if find "$history" -type l -print -quit | grep -q .; then
  record_infrastructure_error 'simulation history contains a symbolic link'
fi

mapfile -d '' history_reports < <(
  find "$history" -type f -name '*.json' -print0 | sort -z
)
if ((${#history_reports[@]} > maximum_history_reports)); then
  record_infrastructure_error \
    "simulation history report bound exceeded: ${#history_reports[@]} > $maximum_history_reports"
  history_reports=("${history_reports[@]:0:maximum_history_reports}")
fi

for report in "${history_reports[@]}"; do
  report_bytes=$(stat -c %s "$report")
  if ((report_bytes > maximum_report_bytes)); then
    record_infrastructure_error "history report exceeds the byte bound: $report"
    continue
  fi
  if ! jq -e "$report_contract" "$report" >/dev/null 2>&1; then
    record_infrastructure_error "malformed history report: $report"
    continue
  fi
  report_time=$(jq -r '.observed_at_unix_secs' "$report")
  if ((report_time < window_start || report_time > window_end)); then
    record_excluded "$report" outside_window
    continue
  fi
  report_policy=$(jq -r '.coverage.policy_blake3' "$report")
  if [[ "$report_policy" != "$current_policy" ]]; then
    record_excluded "$report" policy_revision_mismatch
    continue
  fi
  report_plan=$(jq -r '.seed_leases[0].plan_blake3' "$report")
  if [[ "$report_plan" != "$current_plan" ]]; then
    record_excluded "$report" plan_revision_mismatch
    continue
  fi
  jq -c . "$report" >>"$valid_reports"
done

temporary="$output.tmp.$$"
jq -s \
  --slurpfile excluded "$excluded_reports" \
  --slurpfile initial_errors "$infrastructure_errors" \
  --argjson window_start "$window_start" \
  --argjson window_end "$window_end" \
  '
    def merge_counts($reports; $field):
      [$reports[].coverage[$field][]?]
      | sort_by(.bucket | tojson)
      | group_by(.bucket | tojson)
      | map({
          bucket: .[0].bucket,
          occurrences: (map(.occurrences) | add)
        });
    def intersect_missing($reports; $field):
      reduce $reports[1:][] as $report
        ($reports[0].coverage[$field];
         . as $current
         | [$current[]
            | . as $candidate
            | select(any($report.coverage[$field][]; . == $candidate))]);

    sort_by(.observed_at_unix_secs, .workflow_run_id)
    | . as $reports
    | ([$reports | group_by(.workflow_run_id)[] | select(length > 1) | .[0].workflow_run_id])
      as $duplicate_runs
    | ([$reports[].seed_leases[]] | sort_by(.policy_blake3, .seed_start)) as $seed_leases
    | (if ($seed_leases | length) < 2 then [] else [
        range(1; $seed_leases | length) as $index
        | select(
            $seed_leases[$index - 1].policy_blake3 == $seed_leases[$index].policy_blake3
            and $seed_leases[$index - 1].seed_end_exclusive > $seed_leases[$index].seed_start
          )
        | {
            first: $seed_leases[$index - 1],
            second: $seed_leases[$index]
          }
      ] end) as $overlaps
    | ($initial_errors
       + (if ($duplicate_runs | length) == 0 then []
          else ["duplicate workflow runs: \($duplicate_runs | map(tostring) | join(", "))"] end)
       + (if ($overlaps | length) == 0 then []
          else ["overlapping seed leases: \($overlaps | length)"] end)) as $infrastructure_errors
    | {
        schema_version: 1,
        status: "pending",
        policy_id: $reports[-1].coverage.policy_id,
        policy_blake3: $reports[-1].coverage.policy_blake3,
        plan_blake3: $reports[-1].seed_leases[0].plan_blake3,
        window_start_unix_secs: $window_start,
        window_end_unix_secs: $window_end,
        included_runs: ([$reports[].workflow_run_id] | unique | sort),
        source_revisions: ([$reports[].source_revision] | unique | sort),
        excluded_reports: $excluded,
        coverage: {
          schema_version: 2,
          policy_id: $reports[-1].coverage.policy_id,
          policy_blake3: $reports[-1].coverage.policy_blake3,
          rolling_window_days: 7,
          completed_runs: ([$reports[].coverage.completed_runs] | add),
          observed_individuals: merge_counts($reports; "observed_individuals"),
          missing_individuals: intersect_missing($reports; "missing_individuals"),
          observed_pairs: merge_counts($reports; "observed_pairs"),
          missing_pairs: intersect_missing($reports; "missing_pairs"),
          observed_higher_order: merge_counts($reports; "observed_higher_order"),
          missing_higher_order: intersect_missing($reports; "missing_higher_order"),
          observed_transitions: merge_counts($reports; "observed_transitions"),
          missing_transitions: intersect_missing($reports; "missing_transitions"),
          observed_oracles: merge_counts($reports; "observed_oracles"),
          missing_oracles: intersect_missing($reports; "missing_oracles"),
          observed_phases: merge_counts($reports; "observed_phases"),
          missing_phases: intersect_missing($reports; "missing_phases"),
          known_gaps: $reports[-1].coverage.known_gaps
        },
        seed_leases: $seed_leases,
        overlapping_seed_leases: $overlaps,
        infrastructure_errors: $infrastructure_errors
      }
    | .gaps = (
        ([.coverage.missing_individuals[]
          | {class: "individual", reason: "not_observed_in_rolling_window", bucket: .}]
         + [.coverage.missing_pairs[]
          | {class: "pair", reason: "not_observed_in_rolling_window", bucket: .}]
         + [.coverage.missing_higher_order[]
          | {class: "higher_order", reason: "not_observed_in_rolling_window", bucket: .}]
         + [.coverage.missing_transitions[]
          | {class: "transition", reason: "not_observed_in_rolling_window", bucket: .}]
         + [.coverage.missing_oracles[]
          | {class: "oracle", reason: "not_observed_in_rolling_window", bucket: .}]
         + [.coverage.missing_phases[]
          | {class: "phase", reason: "not_observed_in_rolling_window", bucket: .}]
         + [.coverage.known_gaps[]
          | {class: "known_unsupported", id, dimension, reason}])
      )
    | .status = (
        if (.infrastructure_errors | length) > 0 then "infrastructure_failure"
        elif (.gaps | length) > 0 then "coverage_gaps"
        else "complete"
        end
      )
  ' "$valid_reports" >"$temporary"
mv "$temporary" "$output"

if [[ $(jq -r '.status' "$output") == infrastructure_failure ]]; then
  exit 2
fi
