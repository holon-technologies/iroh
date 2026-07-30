#!/usr/bin/env bash

set -euo pipefail

repository=
revision=
now_unix_secs=
policy=
output=
maximum_policy_bytes=1048576
maximum_api_bytes=8388608

usage() {
  printf '%s\n' \
    'Usage: check-simulation-release-readiness.sh --repository OWNER/REPO --revision HEX --now-unix-secs N --policy PATH --output PATH'
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
    --revision)
      revision=$2
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
      printf 'unknown simulation release readiness argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$repository" || -z "$revision" || -z "$now_unix_secs" \
      || -z "$policy" || -z "$output" ]]; then
  echo "all simulation release readiness arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ \
      || ! "$revision" =~ ^[0-9a-f]{40}$ \
      ]] || ! valid_nonnegative_i64 "$now_unix_secs"; then
  echo "simulation release readiness identity is malformed" >&2
  exit 64
fi
if [[ ! -f "$policy" || -L "$policy" || $(stat -c %s "$policy") -gt $maximum_policy_bytes ]]; then
  echo "simulation release policy is missing, unsafe, or exceeds its byte bound" >&2
  exit 66
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI is required for simulation release readiness" >&2
  exit 66
fi
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
if [[ -e "$output" || -L "$output" ]]; then
  echo "simulation release readiness output must not already exist" >&2
  exit 73
fi
mkdir -p "$(dirname "$output")"

if ! jq -e '
  .schema_version == 7
  and (.release | type == "object")
  and .release.required_same_revision_checks == [
    "Deterministic simulation change gate",
    "Deterministic simulation contracts and corpus",
    "netsim-release / Netsim"
  ]
  and .release.maximum_open_product_failures == 0
  and .release.parity_workflow == "patchbay-hosted-smoke.yml"
  and (.release.maximum_parity_age_hours
    | type == "number" and . > 0 and . <= 744 and floor == .)
  and .release.maximum_parity_age_hours == .parity.maximum_evidence_age_hours
  and .release.maximum_check_runs == 100
  and .release.maximum_issue_results == 100
  and .release.maximum_parity_runs == 8
' "$policy" >/dev/null; then
  echo "simulation release policy is malformed or unsafe" >&2
  exit 65
fi

required_checks=$(jq -c '.release.required_same_revision_checks' "$policy")
maximum_open_product_failures=$(jq -er '.release.maximum_open_product_failures' "$policy")
parity_workflow=$(jq -er '.release.parity_workflow' "$policy")
maximum_parity_age_hours=$(jq -er '.release.maximum_parity_age_hours' "$policy")
maximum_check_runs=$(jq -er '.release.maximum_check_runs' "$policy")
maximum_issue_results=$(jq -er '.release.maximum_issue_results' "$policy")
maximum_parity_runs=$(jq -er '.release.maximum_parity_runs' "$policy")
maximum_parity_age_secs=$((maximum_parity_age_hours * 60 * 60))
open_product_failures='[]'
parity_evidence='null'

publish() {
  local status=$1
  local reason=$2
  local temporary="$output.tmp.$$"
  jq -n \
    --arg status "$status" \
    --arg reason "$reason" \
    --arg repository "$repository" \
    --arg revision "$revision" \
    --argjson observed_at_unix_secs "$now_unix_secs" \
    --argjson required_checks "$required_checks" \
    --argjson open_product_failures "$open_product_failures" \
    --argjson parity "$parity_evidence" \
    '{
      schema_version: 1,
      status: $status,
      reason: $reason,
      repository: $repository,
      revision: $revision,
      observed_at_unix_secs: $observed_at_unix_secs,
      required_checks: $required_checks,
      open_product_failures: $open_product_failures,
      parity: $parity
    }' >"$temporary"
  mv "$temporary" "$output"
}

block_release() {
  local reason=$1
  publish release_blocked "$reason"
  printf 'simulation release is blocked: %s\n' "$reason" >&2
  exit 1
}

infrastructure_failure() {
  local reason=$1
  publish infrastructure_failure "$reason"
  printf 'simulation release readiness infrastructure failure: %s\n' "$reason" >&2
  exit 2
}

scratch_root=$(mktemp -d)
trap 'rm -rf "$scratch_root"' EXIT
checks="$scratch_root/checks.json"
issues="$scratch_root/issues.json"
parity_runs="$scratch_root/parity-runs.json"

if ! gh api \
  "repos/$repository/commits/$revision/check-runs?per_page=$maximum_check_runs&filter=latest" \
  >"$checks"; then
  infrastructure_failure "GitHub check-run query failed"
fi
if (( $(stat -c %s "$checks") > maximum_api_bytes )) \
  || ! jq -e \
    --arg revision "$revision" \
    --argjson maximum "$maximum_check_runs" '
      def uint: type == "number" and . >= 0 and floor == .;
      . as $response
      | type == "object"
      and (.total_count | uint and . <= $maximum)
      and (.check_runs | type == "array" and length == $response.total_count)
      and all(.check_runs[];
        type == "object"
        and (.name | type == "string" and length > 0 and length <= 255)
        and .head_sha == $revision
        and (.status | type == "string")
        and (.conclusion == null or (.conclusion | type == "string"))
        and .app.slug == "github-actions")
    ' "$checks" >/dev/null; then
  infrastructure_failure "GitHub check-run evidence is malformed or exceeds bounds"
fi

while IFS= read -r required_check; do
  if ! jq -e \
    --arg name "$required_check" '
      [.check_runs[] | select(.name == $name)]
      | length == 1
        and .[0].status == "completed"
        and .[0].conclusion == "success"
        and .[0].app.slug == "github-actions"
    ' "$checks" >/dev/null; then
    block_release "required same-revision check is absent, duplicated, or unsuccessful: $required_check"
  fi
done < <(jq -r '.[]' <<<"$required_checks")

if ! gh api search/issues \
  --method GET \
  -f "q=repo:$repository is:issue is:open label:simulation" \
  -f "per_page=$maximum_issue_results" \
  >"$issues"; then
  infrastructure_failure "GitHub simulation issue query failed"
fi
if (( $(stat -c %s "$issues") > maximum_api_bytes )) \
  || ! jq -e \
    --arg repository "$repository" \
    --argjson maximum "$maximum_issue_results" '
      def uint: type == "number" and . > 0 and floor == .;
      . as $response
      | type == "object"
      and .incomplete_results == false
      and (.total_count | type == "number" and . >= 0 and . <= $maximum and floor == .)
      and (.items | type == "array" and length == $response.total_count)
      and all(.items[];
        type == "object"
        and (.number | uint)
        and .html_url == (
          "https://github.com/" + $repository + "/issues/" + (.number | tostring)
        )
        and (.body == null or (.body | type == "string" and length <= 65536))
        and (.labels | type == "array" and length <= 100)
        and all(.labels[];
          type == "object" and (.name | type == "string" and length <= 100)))
    ' "$issues" >/dev/null; then
  infrastructure_failure "GitHub simulation issue evidence is malformed or exceeds bounds"
fi
open_product_failures=$(jq -c '[
  .items[]
  | select((.body // "") | test("<!-- krikos-sim-signature:[0-9a-f]{64} -->"))
  | {
      number,
      url: .html_url,
      signature_digest: (
        .body
        | capture("<!-- krikos-sim-signature:(?<digest>[0-9a-f]{64}) -->").digest
      )
    }
] | sort_by(.number)' "$issues")
if (( $(jq -r 'length' <<<"$open_product_failures") > maximum_open_product_failures )); then
  block_release "one or more confirmed simulation product failures remain open"
fi

if ! gh run list \
  --repo "$repository" \
  --workflow "$parity_workflow" \
  --status success \
  --limit "$maximum_parity_runs" \
  --json databaseId,headSha,createdAt,conclusion,event \
  >"$parity_runs"; then
  infrastructure_failure "GitHub parity workflow query failed"
fi
if (( $(stat -c %s "$parity_runs") > maximum_api_bytes )) \
  || ! jq -e \
    --argjson maximum "$maximum_parity_runs" \
    --argjson now "$now_unix_secs" '
      def uint: type == "number" and . > 0 and floor == .;
      type == "array"
      and length <= $maximum
      and all(.[].databaseId; uint)
      and all(.[].headSha; type == "string" and test("^[0-9a-f]{40}$"))
      and all(.[].createdAt;
        type == "string" and fromdateiso8601 <= $now)
      and all(.[].conclusion; . == "success")
      and all(.[].event; . == "schedule" or . == "workflow_dispatch")
      and ([.[].databaseId] | unique | length) == length
    ' "$parity_runs" >/dev/null; then
  infrastructure_failure "GitHub parity evidence is malformed or exceeds bounds"
fi
parity_evidence=$(jq -c \
  --argjson now "$now_unix_secs" \
  --argjson maximum_age "$maximum_parity_age_secs" '
    [.
      | .[]
      | select(.createdAt | fromdateiso8601 >= ($now - $maximum_age))
    ]
    | sort_by(.createdAt, .databaseId)
    | last
    | if . == null then null
      else {
        workflow_run_id: .databaseId,
        source_revision: .headSha,
        observed_at_unix_secs: (.createdAt | fromdateiso8601)
      }
      end
  ' "$parity_runs")
if [[ "$parity_evidence" == null ]]; then
  block_release "no successful parity evidence is within the maximum age"
fi

publish release_ready "all release simulation evidence is satisfied"
