#!/usr/bin/env bash

set -euo pipefail

repository=
now_unix_secs=
policy=
output=
maximum_policy_bytes=1048576
maximum_api_bytes=8388608

usage() {
  printf '%s\n' \
    'Usage: audit-simulation-gate-runtime-slo.sh --repository OWNER/REPO --now-unix-secs N --policy PATH --output PATH'
}

valid_nonnegative_i64() {
  local value=$1
  local maximum=9223372036854775807
  [[ "$value" =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
  if ((${#value} == ${#maximum})) && [[ "$value" > "$maximum" ]]; then
    return 1
  fi
}

while (($# > 0)); do
  case "$1" in
    --repository)
      repository=$2
      shift 2
      ;;
    --now-unix-secs)
      now_unix_secs=$2
      shift 2
      ;;
    --policy)
      policy=$2
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
      printf 'unknown simulation gate runtime SLO argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$repository" || -z "$now_unix_secs" || -z "$policy" || -z "$output" ]]; then
  echo "all simulation gate runtime SLO arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || ! valid_nonnegative_i64 "$now_unix_secs"; then
  echo "simulation gate runtime SLO identity is malformed" >&2
  exit 64
fi
if [[ ! -f "$policy" || -L "$policy" || $(stat -c %s "$policy") -gt $maximum_policy_bytes ]]; then
  echo "simulation runtime SLO policy is missing, unsafe, or exceeds its byte bound" >&2
  exit 66
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI is required for simulation gate runtime SLO audit" >&2
  exit 66
fi
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
if [[ -e "$output" || -L "$output" ]]; then
  echo "simulation gate runtime SLO output must not already exist" >&2
  exit 73
fi
mkdir -p "$(dirname "$output")"

if ! jq -e '
  .schema_version == 7
  and .gate_runtime_slo == {
    workflow: "ci.yml",
    sample_size: 20,
    percentile: 95,
    pull_request_maximum_minutes: 15,
    main_maximum_minutes: 30,
    maximum_candidate_runs_per_tier: 40,
    maximum_jobs_per_run: 100
  }
' "$policy" >/dev/null; then
  echo "simulation gate runtime SLO policy is malformed or unsafe" >&2
  exit 65
fi

workflow=$(jq -er '.gate_runtime_slo.workflow' "$policy")
sample_size=$(jq -er '.gate_runtime_slo.sample_size' "$policy")
percentile=$(jq -er '.gate_runtime_slo.percentile' "$policy")
pull_request_maximum_minutes=$(jq -er '.gate_runtime_slo.pull_request_maximum_minutes' "$policy")
main_maximum_minutes=$(jq -er '.gate_runtime_slo.main_maximum_minutes' "$policy")
maximum_candidate_runs=$(jq -er '.gate_runtime_slo.maximum_candidate_runs_per_tier' "$policy")
maximum_jobs_per_run=$(jq -er '.gate_runtime_slo.maximum_jobs_per_run' "$policy")
required_jobs='["Deterministic simulation change gate","Deterministic simulation contracts and corpus"]'
tiers='[]'

publish() {
  local status=$1
  local reason=$2
  local temporary="$output.tmp.$$"
  jq -n \
    --arg status "$status" \
    --arg reason "$reason" \
    --arg repository "$repository" \
    --arg workflow "$workflow" \
    --argjson observed_at_unix_secs "$now_unix_secs" \
    --argjson sample_size "$sample_size" \
    --argjson percentile "$percentile" \
    --argjson tiers "$tiers" \
    '{
      schema_version: 1,
      status: $status,
      reason: $reason,
      repository: $repository,
      workflow: $workflow,
      observed_at_unix_secs: $observed_at_unix_secs,
      sample_size: $sample_size,
      percentile: $percentile,
      tiers: $tiers
    }' >"$temporary"
  mv "$temporary" "$output"
}

infrastructure_failure() {
  local reason=$1
  publish infrastructure_failure "$reason"
  printf 'simulation gate runtime SLO infrastructure failure: %s\n' "$reason" >&2
  exit 2
}

scratch_root=$(mktemp -d)
trap 'rm -rf "$scratch_root"' EXIT

collect_tier() {
  local tier=$1
  local event=$2
  local maximum_minutes=$3
  local run_list="$scratch_root/$tier-runs.json"
  local samples="$scratch_root/$tier-samples.jsonl"
  : >"$samples"

  if ! gh run list \
    --repo "$repository" \
    --workflow "$workflow" \
    --event "$event" \
    --status success \
    --limit "$maximum_candidate_runs" \
    --json databaseId,headSha,createdAt,conclusion,event \
    >"$run_list"; then
    infrastructure_failure "GitHub $tier runtime history query failed"
  fi
  if (( $(stat -c %s "$run_list") > maximum_api_bytes )) \
    || ! jq -e \
      --arg event "$event" \
      --argjson now "$now_unix_secs" \
      --argjson maximum "$maximum_candidate_runs" '
        def uint: type == "number" and . > 0 and floor == .;
        type == "array"
        and length <= $maximum
        and all(.[].databaseId; uint)
        and all(.[].headSha; type == "string" and test("^[0-9a-f]{40}$"))
        and all(.[].createdAt;
          type == "string" and fromdateiso8601 <= $now)
        and all(.[].conclusion; . == "success")
        and all(.[].event; . == $event)
        and ([.[].databaseId] | unique | length) == length
      ' "$run_list" >/dev/null; then
    infrastructure_failure "GitHub $tier runtime history is malformed or exceeds bounds"
  fi

  while IFS=$'\t' read -r run_id head_sha; do
    if (( $(wc -l <"$samples") >= sample_size )); then
      break
    fi
    local detail="$scratch_root/$tier-$run_id.json"
    if ! gh run view "$run_id" \
      --repo "$repository" \
      --json databaseId,event,headSha,conclusion,jobs \
      >"$detail"; then
      infrastructure_failure "GitHub $tier workflow-run detail query failed for $run_id"
    fi
    if (( $(stat -c %s "$detail") > maximum_api_bytes )) \
      || ! jq -e \
        --argjson run_id "$run_id" \
        --arg event "$event" \
        --arg head_sha "$head_sha" \
        --argjson maximum_jobs "$maximum_jobs_per_run" '
          type == "object"
          and .databaseId == $run_id
          and .event == $event
          and .headSha == $head_sha
          and .conclusion == "success"
          and (.jobs | type == "array" and length <= $maximum_jobs)
          and all(.jobs[];
            type == "object"
            and (.name | type == "string" and length > 0 and length <= 255)
            and (.conclusion | type == "string"))
        ' "$detail" >/dev/null; then
      infrastructure_failure "GitHub $tier workflow-run detail is malformed for $run_id"
    fi

    local matched_jobs
    matched_jobs=$(jq -c --argjson required "$required_jobs" '[
      $required[] as $name
      | [.jobs[] | select(.name == $name)]
    ]' "$detail")
    local matched_count
    matched_count=$(jq -r 'map(length) | add // 0' <<<"$matched_jobs")
    if [[ "$matched_count" -eq 0 ]]; then
      continue
    fi
    if ! jq -e '
      length == 2
      and all(.[]; length == 1)
      and all(.[][];
        .conclusion == "success"
        and (.startedAt | type == "string")
        and (.completedAt | type == "string")
        and (.startedAt | fromdateiso8601) <= (.completedAt | fromdateiso8601))
    ' <<<"$matched_jobs" >/dev/null; then
      infrastructure_failure "GitHub $tier simulation jobs are absent, duplicated, or malformed for $run_id"
    fi
    local duration_seconds
    duration_seconds=$(jq -r '
      ([.[][] | .startedAt | fromdateiso8601] | min) as $started
      | ([.[][] | .completedAt | fromdateiso8601] | max) as $completed
      | $completed - $started
    ' <<<"$matched_jobs")
    if [[ ! "$duration_seconds" =~ ^[0-9]+$ ]] || ((duration_seconds > 86400)); then
      infrastructure_failure "GitHub $tier simulation duration is invalid for $run_id"
    fi
    jq -cn \
      --argjson workflow_run_id "$run_id" \
      --argjson duration_seconds "$duration_seconds" \
      '{workflow_run_id: $workflow_run_id, duration_seconds: $duration_seconds}' \
      >>"$samples"
  done < <(
    jq -r 'sort_by(.databaseId) | reverse[] | [.databaseId, .headSha] | @tsv' "$run_list"
  )

  local sample_count
  sample_count=$(wc -l <"$samples")
  local maximum_seconds=$((maximum_minutes * 60))
  local p95_seconds=null
  local status=insufficient_history
  if ((sample_count == sample_size)); then
    local rank=$(((percentile * sample_size + 99) / 100))
    local index=$((rank - 1))
    p95_seconds=$(jq -s --argjson index "$index" 'map(.duration_seconds) | sort | .[$index]' "$samples")
    status=within_slo
    if ((p95_seconds > maximum_seconds)); then
      status=slo_breach
    fi
  fi
  local tier_report
  tier_report=$(jq -s \
    --arg tier "$tier" \
    --arg event "$event" \
    --arg status "$status" \
    --argjson samples "$sample_count" \
    --argjson p95_seconds "$p95_seconds" \
    --argjson maximum_seconds "$maximum_seconds" '
      {
        tier: $tier,
        event: $event,
        samples: $samples,
        p95_seconds: $p95_seconds,
        maximum_seconds: $maximum_seconds,
        status: $status,
        workflow_run_ids: (map(.workflow_run_id) | sort)
      }
    ' "$samples")
  tiers=$(jq -c --argjson report "$tier_report" '. + [$report] | sort_by(.tier)' <<<"$tiers")
}

collect_tier pull_request pull_request "$pull_request_maximum_minutes"
collect_tier main push "$main_maximum_minutes"

if jq -e 'any(.[]; .status == "slo_breach")' <<<"$tiers" >/dev/null; then
  publish slo_breach "one or more simulation gate runtime SLOs exceeded P95"
  exit 1
fi
if jq -e 'any(.[]; .status == "insufficient_history")' <<<"$tiers" >/dev/null; then
  publish insufficient_history "fewer than 20 compatible successful runs are available"
  exit 0
fi
publish within_slo "both simulation gate runtime SLOs are satisfied"
