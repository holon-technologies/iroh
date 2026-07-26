#!/usr/bin/env bash

set -euo pipefail

artifact_root=
output=

usage() {
  printf '%s\n' \
    'Usage: aggregate-daily-simulation-soak.sh --artifacts PATH --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --artifacts)
      artifact_root=$2
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

if [[ -z "$artifact_root" || -z "$output" ]]; then
  echo "--artifacts and --output are required" >&2
  usage >&2
  exit 64
fi

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
  def valid_failure($lane):
    type == "object"
    and (.signature | type == "object")
    and .first_lane_id == $lane
    and (.first_seed | uint)
    and (.occurrences | uint and . > 0);
  def valid_summary($epoch; $lane; $seed_window):
    type == "object"
    and .schema_version == 1
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
  '
    def sum_field($field): map(.[$field]) | add // 0;
    def sum_total($field): map(.totals[$field]) | add // 0;

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
