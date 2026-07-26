#!/usr/bin/env bash

set -euo pipefail

artifact_root=
source_revision=
workflow_run_id=
observed_at_unix_secs=
output=

usage() {
  printf '%s\n' \
    'Usage: aggregate-daily-simulation-soak.sh --artifacts PATH --source-revision HEX --workflow-run-id N --observed-at-unix-secs N --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --artifacts)
      artifact_root=$2
      shift 2
      ;;
    --source-revision)
      source_revision=$2
      shift 2
      ;;
    --workflow-run-id)
      workflow_run_id=$2
      shift 2
      ;;
    --observed-at-unix-secs)
      observed_at_unix_secs=$2
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
      printf 'unknown daily simulation aggregate argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$artifact_root" || -z "$source_revision" || -z "$workflow_run_id" \
      || -z "$observed_at_unix_secs" || -z "$output" ]]; then
  echo "all aggregate provenance and path arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! "$source_revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "--source-revision must be exactly 40 lowercase hexadecimal characters" >&2
  exit 64
fi
for value_name in workflow_run_id observed_at_unix_secs; do
  value=${!value_name}
  if [[ ! "$value" =~ ^[0-9]+$ ]] || ((10#$value > 9223372036854775807)); then
    printf -- '--%s must be an unsigned 64-bit decimal integer\n' \
      "${value_name//_/-}" >&2
    exit 64
  fi
done

if [[ "$artifact_root" != /* ]]; then
  artifact_root="$PWD/$artifact_root"
fi
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi

artifact_root_existed=false
if [[ -d "$artifact_root" ]]; then
  artifact_root_existed=true
fi

mkdir -p "$(dirname "$output")"
scratch_root=$(mktemp -d)
trap 'rm -rf "$scratch_root"' EXIT
valid_reports="$scratch_root/valid-reports.jsonl"
infrastructure_errors="$scratch_root/infrastructure-errors.jsonl"
: >"$valid_reports"
: >"$infrastructure_errors"

record_infrastructure_error() {
  jq -cn --arg message "$1" '$message' >>"$infrastructure_errors"
}

reports=()
if [[ "$artifact_root_existed" == true ]]; then
  mapfile -d '' reports < <(
    find "$artifact_root" -type f -name daily-soak-summary.json -print0 | sort -z
  )
else
  record_infrastructure_error "artifact root is missing: $artifact_root"
fi

report_contract='
  def uint: type == "number" and . >= 0 and floor == .;
  def digest:
    type == "string"
    and length == 64
    and test("^[0-9a-f]{64}$");
  def valid_counts:
    type == "array"
    and all(.[];
      type == "object"
      and (.bucket | type == "object")
      and (.occurrences | uint and . > 0));
  def valid_coverage($completed):
    type == "object"
    and .schema_version == 2
    and (.policy_id | type == "string" and length > 0 and length <= 128)
    and (.policy_blake3 | digest)
    and .rolling_window_days == 7
    and .completed_runs == $completed
    and (.observed_individuals | valid_counts)
    and (.missing_individuals | type == "array")
    and (.observed_pairs | valid_counts)
    and (.missing_pairs | type == "array")
    and (.observed_higher_order | valid_counts)
    and (.missing_higher_order | type == "array")
    and (.observed_transitions | valid_counts)
    and (.missing_transitions | type == "array")
    and (.observed_oracles | valid_counts)
    and (.missing_oracles | type == "array")
    and (.observed_phases | valid_counts)
    and (.missing_phases | type == "array")
    and (.known_gaps | type == "array");
  def valid_lease($epoch; $lane; $seed_window; $policy_blake3):
    type == "object"
    and .schema_version == 2
    and .policy_blake3 == $policy_blake3
    and (.plan_blake3 | digest)
    and .lane_id == $lane
    and .seed_window == $seed_window
    and .epoch == $epoch
    and (.lane_index | uint and . < 32)
    and (.seed_start | uint)
    and (.seed_end_exclusive | uint)
    and .seed_end_exclusive == (.seed_start + 1000000)
    and (.consumed_runs | uint and . <= 1000000);
  def valid_failure($lane):
    type == "object"
    and (.signature | type == "object")
    and .first_lane_id == $lane
    and (.first_seed | uint)
    and (.occurrences | uint and . > 0);
  def valid_summary($epoch; $lane; $seed_window):
    . as $summary
    | type == "object"
    and .schema_version == 2
    and .plan_id == "daily"
    and .epoch == $epoch
    and .seed_window == $seed_window
    and (
      .config == {
        wall_budget_millis: 1800000,
        jobs: 4,
        batch_runs: 64,
        max_runs: 10416
      }
    )
    and (.stop_reason == "wall_budget" or .stop_reason == "run_budget")
    and (.elapsed_millis | uint)
    and (.completed_runs | uint)
    and (.successful_runs | uint)
    and (.failed_runs | uint)
    and (.errored_runs | uint)
    and (.worker_panics | uint)
    and (.completed_runs == (.successful_runs + .failed_runs + .errored_runs))
    and (.worker_panics <= .errored_runs)
    and (.completed_runs <= 10416)
    and (.coverage | valid_coverage(.completed_runs))
    and (.seed_leases | type == "array" and length == 1)
    and (
      .seed_leases[0]
      | valid_lease($epoch; $lane; $seed_window; $summary.coverage.policy_blake3)
    )
    and (
      .failure_artifacts
      | type == "object"
      and (.retained | uint)
      and (.omitted | uint)
      and (.retained_bytes | uint)
      and .byte_budget == 33554432
      and .artifact_budget == 2
      and (
        .infrastructure_error == null
        or (.infrastructure_error | type == "string" and length > 0)
      )
    )
    and (.lanes | type == "array" and length == 1)
    and .lanes[0].id == $lane
    and (.lanes[0].next_seed | uint)
    and .lanes[0].completed_runs == .completed_runs
    and .lanes[0].successful_runs == .successful_runs
    and .lanes[0].failed_runs == .failed_runs
    and .lanes[0].errored_runs == .errored_runs
    and .lanes[0].worker_panics == .worker_panics
    and (.unique_failures | type == "array")
    and all(.unique_failures[]; valid_failure($lane));

  . as $report
  | type == "object"
  and $report.schema_version == 1
  and ($report.status == "success"
       or $report.status == "simulation_failure"
       or $report.status == "infrastructure_failure")
  and ($report.lane | type == "string" and length > 0)
  and ($report.seed_window | uint)
  and $report.configured_epochs == 8
  and $report.completed_epochs == 8
  and $report.max_runs_per_epoch == 10416
  and $report.configured_max_runs == 83328
  and ($report.infrastructure_failures | uint)
  and ($report.simulation_failed_epochs | uint)
  and (
    $report.totals
    | type == "object"
    and (.completed_runs | uint)
    and (.successful_runs | uint)
    and (.failed_runs | uint)
    and (.errored_runs | uint)
    and (.worker_panics | uint)
    and (.retained_failure_artifacts | uint)
    and (.omitted_failure_artifacts | uint)
    and (.retained_failure_artifact_bytes | uint)
  )
  and ($report.totals.completed_runs <= $report.configured_max_runs)
  and (
    $report.totals.completed_runs
    == ($report.totals.successful_runs + $report.totals.failed_runs + $report.totals.errored_runs)
  )
  and ($report.totals.worker_panics <= $report.totals.errored_runs)
  and ($report.coverage | valid_coverage($report.totals.completed_runs))
  and ($report.seed_leases | type == "array" and length == 8)
  and all(
    $report.seed_leases[];
    valid_lease(.epoch; $report.lane; $report.seed_window; $report.coverage.policy_blake3)
  )
  and ($report.epochs | type == "array" and length == 8)
  and ([$report.epochs[].epoch] == [range(0; 8)])
  and all(
    $report.epochs[];
    . as $record
    | ($record.epoch | uint)
    and ($record.exit_code | uint and . <= 255)
    and (
      if $record.summary == null then
        ($record.infrastructure_error | type == "string" and length > 0)
      else
        ($record.summary | valid_summary($record.epoch; $report.lane; $report.seed_window))
      end
    )
  )
  and (
    $report.completed_epochs
    == ([$report.epochs[] | select(.summary != null)] | length)
  )
  and (
    $report.infrastructure_failures
    == ([$report.epochs[]
         | select(
             .summary == null
             or (.summary.failure_artifacts.infrastructure_error // null) != null
           )] | length)
  )
  and (
    $report.simulation_failed_epochs
    == ([$report.epochs[]
         | select(
             .summary != null
             and (
               .exit_code != 0
               or .summary.failed_runs > 0
               or .summary.errored_runs > 0
             )
           )] | length)
  )
  and (
    $report.totals.completed_runs
    == ([$report.epochs[].summary.completed_runs // 0] | add // 0)
  )
  and (
    $report.totals.successful_runs
    == ([$report.epochs[].summary.successful_runs // 0] | add // 0)
  )
  and (
    $report.totals.failed_runs
    == ([$report.epochs[].summary.failed_runs // 0] | add // 0)
  )
  and (
    $report.totals.errored_runs
    == ([$report.epochs[].summary.errored_runs // 0] | add // 0)
  )
  and (
    $report.totals.worker_panics
    == ([$report.epochs[].summary.worker_panics // 0] | add // 0)
  )
  and (
    $report.totals.retained_failure_artifacts
    == ([$report.epochs[].summary.failure_artifacts.retained // 0] | add // 0)
  )
  and (
    $report.totals.omitted_failure_artifacts
    == ([$report.epochs[].summary.failure_artifacts.omitted // 0] | add // 0)
  )
  and (
    $report.totals.retained_failure_artifact_bytes
    == ([$report.epochs[].summary.failure_artifacts.retained_bytes // 0] | add // 0)
  )
  and (
    (
      $report.status == "success"
      and $report.infrastructure_failures == 0
      and $report.simulation_failed_epochs == 0
      and $report.totals.failed_runs == 0
      and $report.totals.errored_runs == 0
      and $report.totals.worker_panics == 0
    )
    or (
      $report.status == "simulation_failure"
      and $report.infrastructure_failures == 0
      and (
        $report.simulation_failed_epochs > 0
        or $report.totals.failed_runs > 0
        or $report.totals.errored_runs > 0
      )
    )
    or (
      $report.status == "infrastructure_failure"
      and $report.infrastructure_failures > 0
    )
  )
  and ($report.unique_failures | type == "array")
  and all($report.unique_failures[]; valid_failure($report.lane) and (.epoch | uint))
  and (
    $report.unique_failures
    == [
      $report.epochs[] as $record
      | $record.summary.unique_failures[]?
      | . + {epoch: $record.epoch}
    ]
  )
  and (
    $report.seed_leases
    == [$report.epochs[].summary.seed_leases[]?]
  )
'

for report in "${reports[@]}"; do
  if jq -e "$report_contract" "$report" >/dev/null 2>&1; then
    jq -c . "$report" >>"$valid_reports"
  else
    record_infrastructure_error "malformed lane report: $report"
  fi
done

temporary="$output.tmp.$$"
jq -s \
  --slurpfile initial_errors "$infrastructure_errors" \
  --argjson report_file_count "${#reports[@]}" \
  --arg source_revision "$source_revision" \
  --argjson workflow_run_id "$workflow_run_id" \
  --argjson observed_at_unix_secs "$observed_at_unix_secs" \
  '
    def sum_field($field): map(.[$field]) | add // 0;
    def sum_total($field): map(.totals[$field]) | add // 0;
    def merge_counts($reports; $field):
      [$reports[][$field][]?]
      | sort_by(.bucket | tojson)
      | group_by(.bucket | tojson)
      | map({
          bucket: .[0].bucket,
          occurrences: (map(.occurrences) | add)
        });
    def intersect_missing($reports; $field):
      if ($reports | length) == 0 then []
      else
        reduce $reports[1:][] as $report
          ($reports[0][$field];
           . as $current
           | [$current[]
              | . as $candidate
              | select(any($report[$field][]; . == $candidate))])
      end;

    [
      "direct/deterministic-test",
      "direct/production-provider",
      "discovery/deterministic-test",
      "discovery/production-provider",
      "mobility/deterministic-test",
      "mobility/production-provider",
      "nat/deterministic-test",
      "nat/production-provider",
      "ready-order/deterministic-test",
      "ready-order/production-provider",
      "relay/deterministic-test",
      "relay/production-provider"
    ] as $expected
    | . as $reports
    | ([$reports[].coverage]) as $coverage_reports
    | ([$reports[].seed_leases[]] | sort_by(.policy_blake3, .seed_start)) as $seed_leases
    | (
        ([$coverage_reports[].policy_id] | unique | length) != 1
        or ([$coverage_reports[].policy_blake3] | unique | length) != 1
        or ([$coverage_reports[].rolling_window_days] | unique | length) != 1
      ) as $coverage_policy_mismatch
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
      ] end) as $overlapping_seed_leases
    | ([$reports[].lane] | unique) as $observed_lanes
    | ($expected - $observed_lanes) as $missing_lanes
    | ($observed_lanes - $expected) as $unexpected_lanes
    | ([$reports | group_by(.lane)[] | select(length > 1) | .[0].lane]) as $duplicate_lanes
    | ([$reports | group_by(.seed_window)[] | select(length > 1) | .[0].seed_window])
      as $duplicate_seed_windows
    | ([$reports[] | select(.status == "infrastructure_failure") | .lane])
      as $infrastructure_failed_lanes
    | (
        $initial_errors
        + (if $report_file_count == 12 then []
           else ["expected 12 reports, received \($report_file_count)"] end)
        + (if ($missing_lanes | length) == 0 then []
           else ["missing lanes: \($missing_lanes | join(", "))"] end)
        + (if ($unexpected_lanes | length) == 0 then []
           else ["unexpected lanes: \($unexpected_lanes | join(", "))"] end)
        + (if ($duplicate_lanes | length) == 0 then []
           else ["duplicate lanes: \($duplicate_lanes | join(", "))"] end)
        + (if ($duplicate_seed_windows | length) == 0 then []
           else ["duplicate seed windows: \($duplicate_seed_windows | map(tostring) | join(", "))"] end)
        + (if ($infrastructure_failed_lanes | length) == 0 then []
           else ["infrastructure-failed lanes: \($infrastructure_failed_lanes | join(", "))"] end)
        + (if $coverage_policy_mismatch then ["coverage policy identity mismatch"] else [] end)
        + (if ($overlapping_seed_leases | length) == 0 then []
           else ["overlapping seed leases: \($overlapping_seed_leases | length)"] end)
      ) as $infrastructure_errors
    | ([
        $reports[] as $report
        | $report.unique_failures[]
        | . + {aggregate_lane: $report.lane}
      ]
      | sort_by(.signature | tojson)
      | group_by(.signature | tojson)
      | map({
          signature: .[0].signature,
          occurrences: (map(.occurrences) | add),
          lanes: (map(.aggregate_lane) | unique | sort)
        })) as $unique_failures
    | {
        schema_version: 1,
        source_revision: $source_revision,
        workflow_run_id: $workflow_run_id,
        observed_at_unix_secs: $observed_at_unix_secs,
        status: (
          if ($infrastructure_errors | length) > 0 then "infrastructure_failure"
          elif any($reports[]; .status == "simulation_failure") then "simulation_failure"
          else "success"
          end
        ),
        expected_lanes: ($expected | length),
        completed_lanes: ([$observed_lanes[] | select(. as $lane | $expected | index($lane))] | length),
        received_reports: $report_file_count,
        configured_epochs: ($reports | sum_field("configured_epochs")),
        completed_epochs: ($reports | sum_field("completed_epochs")),
        configured_max_runs: ($reports | sum_field("configured_max_runs")),
        totals: {
          completed_runs: ($reports | sum_total("completed_runs")),
          successful_runs: ($reports | sum_total("successful_runs")),
          failed_runs: ($reports | sum_total("failed_runs")),
          errored_runs: ($reports | sum_total("errored_runs")),
          worker_panics: ($reports | sum_total("worker_panics")),
          retained_failure_artifacts: ($reports | sum_total("retained_failure_artifacts")),
          omitted_failure_artifacts: ($reports | sum_total("omitted_failure_artifacts")),
          retained_failure_artifact_bytes: (
            $reports | sum_total("retained_failure_artifact_bytes")
          )
        },
        coverage: (
          if ($coverage_reports | length) == 0 then null
          else {
            schema_version: 2,
            policy_id: $coverage_reports[0].policy_id,
            policy_blake3: $coverage_reports[0].policy_blake3,
            rolling_window_days: $coverage_reports[0].rolling_window_days,
            completed_runs: ([$coverage_reports[].completed_runs] | add),
            observed_individuals: merge_counts($coverage_reports; "observed_individuals"),
            missing_individuals: intersect_missing($coverage_reports; "missing_individuals"),
            observed_pairs: merge_counts($coverage_reports; "observed_pairs"),
            missing_pairs: intersect_missing($coverage_reports; "missing_pairs"),
            observed_higher_order: merge_counts($coverage_reports; "observed_higher_order"),
            missing_higher_order: intersect_missing($coverage_reports; "missing_higher_order"),
            observed_transitions: merge_counts($coverage_reports; "observed_transitions"),
            missing_transitions: intersect_missing($coverage_reports; "missing_transitions"),
            observed_oracles: merge_counts($coverage_reports; "observed_oracles"),
            missing_oracles: intersect_missing($coverage_reports; "missing_oracles"),
            observed_phases: merge_counts($coverage_reports; "observed_phases"),
            missing_phases: intersect_missing($coverage_reports; "missing_phases"),
            known_gaps: $coverage_reports[0].known_gaps
          }
          end
        ),
        seed_leases: $seed_leases,
        overlapping_seed_leases: $overlapping_seed_leases,
        unique_failures: $unique_failures,
        infrastructure_errors: $infrastructure_errors,
        lanes: (
          $reports
          | sort_by(.lane)
          | map({
              lane,
              status,
              seed_window,
              configured_epochs,
              completed_epochs,
              configured_max_runs,
              totals
            })
        )
      }
  ' "$valid_reports" >"$temporary"
mv "$temporary" "$output"

status=$(jq -r '.status' "$output")
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Daily deterministic simulation aggregate"
    echo
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Lanes: `%s/%s`\n' \
      "$(jq -r '.completed_lanes' "$output")" \
      "$(jq -r '.expected_lanes' "$output")"
    printf -- '- Runs: `%s` completed of `%s` configured maximum\n' \
      "$(jq -r '.totals.completed_runs' "$output")" \
      "$(jq -r '.configured_max_runs' "$output")"
    printf -- '- Failures: `%s` failed, `%s` errored, `%s` unique signatures\n' \
      "$(jq -r '.totals.failed_runs' "$output")" \
      "$(jq -r '.totals.errored_runs' "$output")" \
      "$(jq -r '.unique_failures | length' "$output")"
  } >>"$GITHUB_STEP_SUMMARY"
fi

case "$status" in
  success)
    exit 0
    ;;
  simulation_failure)
    exit 1
    ;;
  infrastructure_failure)
    exit 2
    ;;
  *)
    printf 'unknown daily simulation aggregate status: %s\n' "$status" >&2
    exit 2
    ;;
esac
