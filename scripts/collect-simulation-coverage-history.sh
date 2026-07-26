#!/usr/bin/env bash

set -euo pipefail

repository=
workflow=
current_run_id=
policy_blake3=
window_start=
window_end=
output=
maximum_runs=32
maximum_report_bytes=16777216
maximum_total_bytes=536870912

usage() {
  printf '%s\n' \
    'Usage: collect-simulation-coverage-history.sh --repository OWNER/REPO --workflow NAME --current-run-id N --policy-blake3 HEX --window-start-unix-secs N --window-end-unix-secs N --output PATH'
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
    --current-run-id)
      current_run_id=$2
      shift 2
      ;;
    --policy-blake3)
      policy_blake3=$2
      shift 2
      ;;
    --window-start-unix-secs)
      window_start=$2
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
      printf 'unknown simulation coverage collection argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$repository" || -z "$workflow" || -z "$current_run_id" \
      || -z "$policy_blake3" || -z "$window_start" || -z "$window_end" \
      || -z "$output" ]]; then
  echo "all coverage history collection arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "--repository must be an OWNER/REPO slug" >&2
  exit 64
fi
if [[ ! "$workflow" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo "--workflow must be a workflow file name" >&2
  exit 64
fi
if [[ ! "$policy_blake3" =~ ^[0-9a-f]{64}$ ]]; then
  echo "--policy-blake3 must be exactly 64 lowercase hexadecimal characters" >&2
  exit 64
fi
for value_name in current_run_id window_start window_end; do
  value=${!value_name}
  if [[ ! "$value" =~ ^[0-9]+$ ]] || ((10#$value > 9223372036854775807)); then
    printf -- '--%s must be an unsigned 64-bit decimal integer\n' \
      "${value_name//_/-}" >&2
    exit 64
  fi
done
if ((10#$window_start > 10#$window_end)); then
  echo "coverage history window start must not exceed its end" >&2
  exit 64
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI is required to collect simulation coverage history" >&2
  exit 2
fi

if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
if [[ -L "$output" ]]; then
  echo "coverage history output must not be a symbolic link" >&2
  exit 66
fi
if [[ -d "$output" ]] && find "$output" -mindepth 1 -print -quit | grep -q .; then
  echo "coverage history output directory must be empty" >&2
  exit 66
fi
mkdir -p "$output"

scratch_root=$(mktemp -d)
trap 'rm -rf "$scratch_root"' EXIT
run_list="$scratch_root/runs.json"
since=$(date -u -d "@$window_start" '+%Y-%m-%dT%H:%M:%SZ')
until=$(date -u -d "@$window_end" '+%Y-%m-%dT%H:%M:%SZ')

if ! gh run list \
  --repo "$repository" \
  --workflow "$workflow" \
  --status completed \
  --created "$since..$until" \
  --limit "$maximum_runs" \
  --json databaseId,headSha,createdAt \
  >"$run_list"; then
  echo "GitHub workflow history query failed" >&2
  exit 2
fi
if (( $(stat -c %s "$run_list") > 1048576 )); then
  echo "GitHub workflow history response exceeds the byte bound" >&2
  exit 2
fi
if ! jq -e \
  --argjson maximum_runs "$maximum_runs" \
  --argjson window_start "$window_start" \
  --argjson window_end "$window_end" \
  '
    def uint: type == "number" and . >= 0 and floor == .;
    type == "array"
    and length <= $maximum_runs
    and all(.[];
      type == "object"
      and (.databaseId | uint and . > 0)
      and (.headSha | type == "string" and test("^[0-9a-f]{40}$"))
      and (.createdAt | type == "string" and fromdateiso8601 >= $window_start)
      and (.createdAt | fromdateiso8601 <= $window_end))
    and ([.[].databaseId] | unique | length) == length
  ' "$run_list" >/dev/null 2>&1; then
  echo "GitHub workflow history response is malformed or out of bounds" >&2
  exit 2
fi

total_bytes=0
while IFS=$'\t' read -r run_id head_sha created_at; do
  if [[ "$run_id" == "$current_run_id" ]]; then
    continue
  fi

  download_root="$scratch_root/run-$run_id"
  mkdir -p "$download_root"
  if ! gh run download "$run_id" \
    --repo "$repository" \
    --name "iroh-sim-soak-aggregate-$run_id" \
    --dir "$download_root"; then
    legacy_download_root="$scratch_root/legacy-run-$run_id"
    mkdir -p "$legacy_download_root"
    if gh run download "$run_id" \
      --repo "$repository" \
      --name "iroh-sim-daily-soak-$run_id" \
      --dir "$legacy_download_root"; then
      printf 'Skipping pre-coverage aggregate artifact for run %s\n' \
        "$run_id" >&2
      continue
    fi
    printf 'GitHub aggregate artifact download failed for run %s\n' "$run_id" >&2
    exit 2
  fi
  if find "$download_root" -type l -print -quit | grep -q .; then
    printf 'GitHub aggregate artifact contains a symbolic link for run %s\n' \
      "$run_id" >&2
    exit 2
  fi
  mapfile -d '' report_files < <(
    find "$download_root" -type f -name daily-soak-aggregate.json -print0
  )
  if ((${#report_files[@]} != 1)); then
    printf 'GitHub aggregate artifact has %d reports for run %s\n' \
      "${#report_files[@]}" "$run_id" >&2
    exit 2
  fi
  report=${report_files[0]}
  report_bytes=$(stat -c %s "$report")
  total_bytes=$((total_bytes + report_bytes))
  if ((report_bytes > maximum_report_bytes || total_bytes > maximum_total_bytes)); then
    printf 'GitHub aggregate artifact exceeds collection bounds for run %s\n' \
      "$run_id" >&2
    exit 2
  fi

  if ! report_policy=$(jq -r '
    if type == "object" then (.coverage.policy_blake3 // "")
    else error("aggregate must be an object")
    end
  ' "$report" 2>/dev/null); then
    printf 'GitHub aggregate artifact is malformed for run %s\n' "$run_id" >&2
    exit 2
  fi
  if [[ -z "$report_policy" ]]; then
    # Aggregates from before coverage-policy provenance was introduced cannot
    # contribute to this policy revision, but they are expected during rollout.
    continue
  fi
  if [[ ! "$report_policy" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'GitHub aggregate artifact has an invalid policy digest for run %s\n' \
      "$run_id" >&2
    exit 2
  fi
  if [[ "$report_policy" != "$policy_blake3" ]]; then
    # A policy revision starts a new coverage window. Older valid reports are
    # deliberately ignored rather than reinterpreted under the current policy.
    continue
  fi

  created_at_unix_secs=$(date -u -d "$created_at" '+%s')
  if ! jq -e \
    --argjson run_id "$run_id" \
    --arg head_sha "$head_sha" \
    --arg policy_blake3 "$policy_blake3" \
    --argjson created_at "$created_at_unix_secs" \
    --argjson window_end "$window_end" \
    '
      def uint: type == "number" and . >= 0 and floor == .;
      type == "object"
      and .schema_version == 1
      and .workflow_run_id == $run_id
      and .source_revision == $head_sha
      and (.observed_at_unix_secs | uint and . >= $created_at and . <= $window_end)
      and (.coverage | type == "object")
      and .coverage.schema_version == 2
      and (.coverage.policy_blake3 | type == "string" and test("^[0-9a-f]{64}$"))
    ' "$report" >/dev/null 2>&1; then
    printf 'GitHub aggregate artifact provenance is invalid for run %s\n' \
      "$run_id" >&2
    exit 2
  fi
  cp "$report" "$output/$run_id.json"
done < <(
  jq -r \
    'sort_by(.databaseId)[] | [.databaseId, .headSha, .createdAt] | @tsv' \
    "$run_list"
)
