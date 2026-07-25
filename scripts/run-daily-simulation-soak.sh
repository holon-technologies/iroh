#!/usr/bin/env bash
# shellcheck disable=SC2016 # Markdown backticks are intentional literal output.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
plan="$repo_root/iroh-sim/soaks/daily.json"
sim_bin="$repo_root/target/release/cargo-sim"
artifact_root=
seed_window=
epochs=8
epoch_seconds=1800
jobs=4
batch_runs=64
max_runs_per_epoch=125000
max_failure_artifacts_per_epoch=2
max_artifact_bytes_per_epoch=33554432

usage() {
  cat <<'USAGE'
Usage: run-daily-simulation-soak.sh --seed-window N --artifacts PATH [options]

Options:
  --plan PATH
  --sim-bin PATH
  --epochs N
  --epoch-seconds N
  --jobs N
  --batch-runs N
  --max-runs-per-epoch N
USAGE
}

while (($# > 0)); do
  case "$1" in
    --plan)
      plan=$2
      shift 2
      ;;
    --sim-bin)
      sim_bin=$2
      shift 2
      ;;
    --seed-window)
      seed_window=$2
      shift 2
      ;;
    --artifacts)
      artifact_root=$2
      shift 2
      ;;
    --epochs)
      epochs=$2
      shift 2
      ;;
    --epoch-seconds)
      epoch_seconds=$2
      shift 2
      ;;
    --jobs)
      jobs=$2
      shift 2
      ;;
    --batch-runs)
      batch_runs=$2
      shift 2
      ;;
    --max-runs-per-epoch)
      max_runs_per_epoch=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown daily simulation soak argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

require_uint() {
  local name=$1
  local value=$2
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    printf '%s must be an unsigned decimal integer: %s\n' "$name" "$value" >&2
    exit 64
  fi
}

if [[ -z "$seed_window" || -z "$artifact_root" ]]; then
  echo "--seed-window and --artifacts are required" >&2
  usage >&2
  exit 64
fi

require_uint "--seed-window" "$seed_window"
require_uint "--epochs" "$epochs"
require_uint "--epoch-seconds" "$epoch_seconds"
require_uint "--jobs" "$jobs"
require_uint "--batch-runs" "$batch_runs"
require_uint "--max-runs-per-epoch" "$max_runs_per_epoch"

if ((epochs < 1 || epochs > 8)); then
  echo "--epochs must be in 1..=8" >&2
  exit 64
fi
if ((epoch_seconds < 1 || epoch_seconds > 1800)); then
  echo "--epoch-seconds must be in 1..=1800" >&2
  exit 64
fi
if ((epochs * epoch_seconds > 14400)); then
  echo "total simulation wall budget must not exceed four hours" >&2
  exit 64
fi
if ((jobs < 1 || jobs > 4)); then
  echo "--jobs must be in 1..=4" >&2
  exit 64
fi
if ((batch_runs < 1 || batch_runs > 64)); then
  echo "--batch-runs must be in 1..=64" >&2
  exit 64
fi
if ((max_runs_per_epoch < 1 || max_runs_per_epoch > 125000)); then
  echo "--max-runs-per-epoch must be in 1..=125000" >&2
  exit 64
fi
if ((epochs * max_runs_per_epoch > 1000000)); then
  echo "total simulation run budget must not exceed 1000000" >&2
  exit 64
fi
if [[ ! -f "$plan" ]]; then
  printf 'daily simulation soak plan is missing: %s\n' "$plan" >&2
  exit 66
fi
if [[ ! -x "$sim_bin" ]]; then
  printf 'cargo-sim binary is not executable: %s\n' "$sim_bin" >&2
  exit 66
fi
if [[ "$artifact_root" != /* ]]; then
  artifact_root="$PWD/$artifact_root"
fi
if [[ -e "$artifact_root" ]]; then
  printf 'daily simulation artifact root already exists: %s\n' "$artifact_root" >&2
  exit 73
fi

mkdir -p "$(dirname "$artifact_root")"
mkdir "$artifact_root"
epoch_results="$artifact_root/epoch-results.jsonl"
: >"$epoch_results"

publish_report() {
  local temporary="$artifact_root/.daily-soak-summary.json.tmp.$$"
  jq -s \
    --argjson seed_window "$seed_window" \
    --argjson configured_epochs "$epochs" \
    '
      . as $records
      | ([$records[]
          | select(
              .summary == null
              or (.summary.failure_artifacts.infrastructure_error // null) != null
            )] | length) as $infrastructure_failures
      | ([$records[]
          | select(
              .summary != null
              and (
                (.exit_code != 0)
                or ((.summary.failed_runs // 0) > 0)
                or ((.summary.errored_runs // 0) > 0)
              )
            )] | length) as $simulation_failed_epochs
      | {
          schema_version: 1,
          status: (
            if $infrastructure_failures > 0 then "infrastructure_failure"
            elif $simulation_failed_epochs > 0 then "simulation_failure"
            else "success"
            end
          ),
          seed_window: $seed_window,
          configured_epochs: $configured_epochs,
          completed_epochs: ([$records[] | select(.summary != null)] | length),
          infrastructure_failures: $infrastructure_failures,
          simulation_failed_epochs: $simulation_failed_epochs,
          totals: {
            completed_runs: ([$records[].summary.completed_runs // 0] | add // 0),
            successful_runs: ([$records[].summary.successful_runs // 0] | add // 0),
            failed_runs: ([$records[].summary.failed_runs // 0] | add // 0),
            errored_runs: ([$records[].summary.errored_runs // 0] | add // 0),
            worker_panics: ([$records[].summary.worker_panics // 0] | add // 0),
            retained_failure_artifacts: (
              [$records[].summary.failure_artifacts.retained // 0] | add // 0
            ),
            omitted_failure_artifacts: (
              [$records[].summary.failure_artifacts.omitted // 0] | add // 0
            ),
            retained_failure_artifact_bytes: (
              [$records[].summary.failure_artifacts.retained_bytes // 0] | add // 0
            )
          },
          unique_failures: [
            $records[] as $record
            | $record.summary.unique_failures[]?
            | . + {epoch: $record.epoch}
          ],
          epochs: $records
        }
    ' "$epoch_results" >"$temporary"
  mv "$temporary" "$artifact_root/daily-soak-summary.json"
}

for ((epoch = 0; epoch < epochs; epoch++)); do
  epoch_root="$artifact_root/epoch-$(printf '%02d' "$epoch")"
  set +e
  "$sim_bin" soak \
    --plan "$plan" \
    --epoch "$epoch" \
    --seed-window "$seed_window" \
    --wall-seconds "$epoch_seconds" \
    --jobs "$jobs" \
    --batch-runs "$batch_runs" \
    --max-runs "$max_runs_per_epoch" \
    --max-failure-artifacts "$max_failure_artifacts_per_epoch" \
    --max-artifact-bytes "$max_artifact_bytes_per_epoch" \
    --artifacts "$epoch_root"
  epoch_status=$?
  set -e

  if [[ -f "$epoch_root/soak-summary.json" ]]; then
    jq -n \
      --argjson epoch "$epoch" \
      --argjson exit_code "$epoch_status" \
      --slurpfile summary "$epoch_root/soak-summary.json" \
      '{epoch: $epoch, exit_code: $exit_code, summary: $summary[0]}' \
      >>"$epoch_results"
  else
    jq -n \
      --argjson epoch "$epoch" \
      --argjson exit_code "$epoch_status" \
      --arg error "epoch did not publish soak-summary.json" \
      '{epoch: $epoch, exit_code: $exit_code, summary: null, infrastructure_error: $error}' \
      >>"$epoch_results"
  fi
  publish_report
done

report="$artifact_root/daily-soak-summary.json"
status=$(jq -r '.status' "$report")
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Daily deterministic simulation soak"
    echo
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Epochs: `%s/%s`\n' \
      "$(jq -r '.completed_epochs' "$report")" \
      "$(jq -r '.configured_epochs' "$report")"
    printf -- '- Runs: `%s` completed, `%s` failed, `%s` errored\n' \
      "$(jq -r '.totals.completed_runs' "$report")" \
      "$(jq -r '.totals.failed_runs' "$report")" \
      "$(jq -r '.totals.errored_runs' "$report")"
    printf -- '- Failure artifacts: `%s` retained, `%s` omitted\n' \
      "$(jq -r '.totals.retained_failure_artifacts' "$report")" \
      "$(jq -r '.totals.omitted_failure_artifacts' "$report")"
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
    printf 'unknown daily simulation soak status: %s\n' "$status" >&2
    exit 2
    ;;
esac
