#!/usr/bin/env bash

set -euo pipefail

repository=
workflow=
policy_blake3=
now_unix_secs=
output=
maximum_runs=8
maximum_artifact_bytes=50331648
maximum_age_secs=172800

usage() {
  printf '%s\n' \
    'Usage: collect-latest-simulation-gap-selection.sh --repository OWNER/REPO --workflow NAME --policy-blake3 HEX --now-unix-secs N --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --repository)
      repository=$2
      shift 2
      ;;
    --workflow)
      workflow=$2
      shift 2
      ;;
    --policy-blake3)
      policy_blake3=$2
      shift 2
      ;;
    --now-unix-secs)
      now_unix_secs=$2
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
      printf 'unknown latest simulation gap argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$repository" || -z "$workflow" || -z "$policy_blake3" \
      || -z "$now_unix_secs" || -z "$output" ]]; then
  echo "all latest simulation gap arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ \
      || ! "$workflow" =~ ^[A-Za-z0-9_.-]+$ \
      || ! "$policy_blake3" =~ ^[0-9a-f]{64}$ \
      || ! "$now_unix_secs" =~ ^[0-9]+$ ]]; then
  echo "latest simulation gap arguments are malformed" >&2
  exit 64
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI is required to collect the latest simulation gaps" >&2
  exit 2
fi
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
if [[ -e "$output" || -L "$output" ]]; then
  echo "latest simulation gap output must not already exist" >&2
  exit 73
fi
mkdir -p "$(dirname "$output")"

scratch_root=$(mktemp -d)
trap 'rm -rf "$scratch_root"' EXIT
run_list="$scratch_root/runs.json"
if ! gh run list \
  --repo "$repository" \
  --workflow "$workflow" \
  --status completed \
  --limit "$maximum_runs" \
  --json databaseId,headSha,createdAt \
  >"$run_list"; then
  echo "GitHub daily simulation query failed" >&2
  exit 2
fi
if ! jq -e \
  --argjson maximum_runs "$maximum_runs" \
  --argjson now "$now_unix_secs" \
  --argjson maximum_age "$maximum_age_secs" \
  '
    def uint: type == "number" and . > 0 and floor == .;
    type == "array"
    and length <= $maximum_runs
    and all(.[];
      (.databaseId | uint)
      and (.headSha | type == "string" and test("^[0-9a-f]{40}$"))
      and (.createdAt | type == "string")
      and (.createdAt | fromdateiso8601 <= $now)
      and (.createdAt | fromdateiso8601 >= ($now - $maximum_age)))
    and ([.[].databaseId] | unique | length) == length
  ' "$run_list" >/dev/null 2>&1; then
  echo "GitHub daily simulation query returned malformed or stale metadata" >&2
  exit 2
fi

while IFS=$'\t' read -r run_id head_sha; do
  download_root="$scratch_root/run-$run_id"
  mkdir -p "$download_root"
  if ! gh run download "$run_id" \
    --repo "$repository" \
    --name "iroh-sim-soak-aggregate-$run_id" \
    --dir "$download_root" \
    >/dev/null 2>&1; then
    continue
  fi
  if find "$download_root" -type l -print -quit | grep -q .; then
    echo "daily simulation aggregate artifact contains a symbolic link" >&2
    exit 2
  fi
  total_bytes=$(find "$download_root" -type f -printf '%s\n' | awk '{sum += $1} END {print sum + 0}')
  if ((total_bytes > maximum_artifact_bytes)); then
    echo "daily simulation aggregate artifact exceeds the byte bound" >&2
    exit 2
  fi
  aggregate="$download_root/daily-soak-aggregate.json"
  rolling="$download_root/rolling-coverage.json"
  gaps="$download_root/gap-selection.json"
  if [[ ! -f "$aggregate" ]]; then
    continue
  fi
  report_policy=$(jq -er '.coverage.policy_blake3 // empty' "$aggregate" 2>/dev/null || true)
  if [[ "$report_policy" != "$policy_blake3" ]]; then
    continue
  fi
  if [[ ! -f "$rolling" || ! -f "$gaps" ]] \
    || ! jq -e \
      --argjson run_id "$run_id" \
      --arg head_sha "$head_sha" \
      --arg policy "$policy_blake3" \
      '
        .schema_version == 1
        and .workflow_run_id == $run_id
        and .source_revision == $head_sha
        and .coverage.policy_blake3 == $policy
      ' "$aggregate" >/dev/null \
    || ! jq -e \
      --argjson run_id "$run_id" \
      --arg policy "$policy_blake3" \
      '
        .schema_version == 1
        and .policy_blake3 == $policy
        and (.included_runs | type == "array" and index($run_id) != null)
      ' "$rolling" >/dev/null \
    || ! jq -e \
      --arg policy "$policy_blake3" \
      '
        .schema_version == 1
        and .policy_blake3 == $policy
        and (.lanes | type == "array" and length <= 12)
        and all(.lanes[];
          (.lane | type == "string" and test("^(direct|discovery|mobility|nat|ready-order|relay)/(deterministic-test|production-provider)$")))
        and ([.lanes[].lane] | unique | length) == (.lanes | length)
      ' "$gaps" >/dev/null; then
    printf 'latest compatible simulation gap evidence is malformed for run %s\n' \
      "$run_id" >&2
    exit 2
  fi
  jq -n \
    --argjson source_workflow_run_id "$run_id" \
    --arg source_revision "$head_sha" \
    --arg policy_blake3 "$policy_blake3" \
    --slurpfile gaps "$gaps" \
    '{
      schema_version: 1,
      source_workflow_run_id: $source_workflow_run_id,
      source_revision: $source_revision,
      policy_blake3: $policy_blake3,
      lanes: ($gaps[0].lanes | map(.lane) | sort),
      gap_count: ($gaps[0].lanes | map(.gap_count) | add // 0)
    }' >"$output"
  exit 0
done < <(
  jq -r 'sort_by(.databaseId) | reverse[] | [.databaseId, .headSha] | @tsv' "$run_list"
)

echo "no fresh compatible simulation gap selection is available" >&2
exit 3
