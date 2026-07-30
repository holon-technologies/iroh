#!/usr/bin/env bash

set -euo pipefail

event=
repository=
revision=
corpus=
checks=
sim_bin=
output=
maximum_event_bytes=1048576
maximum_checks_bytes=8388608
maximum_metadata_bytes=131072
maximum_scenario_bytes=16777216
maximum_entries=4096
maximum_check_runs=100

usage() {
  printf '%s\n' \
    'Usage: check-simulation-issue-closure.sh --event PATH --repository OWNER/REPO --revision HEX --corpus PATH --checks PATH --sim-bin PATH --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --event)
      event=$2
      shift 2
      ;;
    --repository)
      repository=$2
      shift 2
      ;;
    --revision)
      revision=$2
      shift 2
      ;;
    --corpus)
      corpus=$2
      shift 2
      ;;
    --checks)
      checks=$2
      shift 2
      ;;
    --sim-bin)
      sim_bin=$2
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
      printf 'unknown simulation issue closure argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$event" || -z "$repository" || -z "$revision" || -z "$corpus" \
      || -z "$checks" || -z "$sim_bin" || -z "$output" ]]; then
  echo "all simulation issue closure arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ \
      || ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "simulation issue closure repository or revision is malformed" >&2
  exit 64
fi
for input in "$event" "$checks"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    printf 'simulation issue closure input is missing or unsafe: %s\n' "$input" >&2
    exit 66
  fi
done
if [[ ! -d "$corpus" || -L "$corpus" || ! -x "$sim_bin" || -L "$sim_bin" ]]; then
  echo "simulation issue closure corpus or simulator is missing or unsafe" >&2
  exit 66
fi
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
if [[ -e "$output" || -L "$output" ]]; then
  echo "simulation issue closure output must not already exist" >&2
  exit 73
fi
if (( $(stat -c %s "$event") > maximum_event_bytes \
      || $(stat -c %s "$checks") > maximum_checks_bytes )); then
  echo "simulation issue closure input exceeds its byte bound" >&2
  exit 65
fi
if find "$corpus" -type l -print -quit | grep -q .; then
  echo "simulation corpus contains a symbolic link" >&2
  exit 65
fi

if ! jq -e \
  --arg repository "$repository" '
    def uint: type == "number" and . > 0 and floor == .;
    type == "object"
    and .action == "closed"
    and .repository.full_name == $repository
    and (.repository.default_branch | type == "string" and length > 0 and length <= 255)
    and (.issue.number | uint)
    and .issue.html_url == (
      "https://github.com/" + $repository + "/issues/" + (.issue.number | tostring)
    )
    and (.issue.body | type == "string" and length <= 65536)
    and (.issue.labels | type == "array" and length <= 100)
    and all(.issue.labels[];
      type == "object" and (.name | type == "string" and length <= 100))
    and any(.issue.labels[]; .name == "simulation")
    and ([.issue.body | scan("<!-- krikos-sim-signature:[0-9a-f]{64} -->")] | length) == 1
  ' "$event" >/dev/null; then
  echo "closed issue event is not one bounded tracked simulation failure" >&2
  exit 1
fi

issue_number=$(jq -er '.issue.number' "$event")
issue_url=$(jq -er '.issue.html_url' "$event")
signature_digest=$(jq -er '
  .issue.body
  | capture("<!-- krikos-sim-signature:(?<digest>[0-9a-f]{64}) -->").digest
' "$event")

if ! jq -e \
  --arg revision "$revision" \
  --argjson maximum "$maximum_check_runs" '
    def uint: type == "number" and . >= 0 and floor == .;
    . as $checks
    | type == "object"
    and (.total_count | uint and . <= $maximum)
    and (.check_runs | type == "array" and length == $checks.total_count)
    and all(.check_runs[];
      type == "object"
      and (.name | type == "string" and length > 0 and length <= 255)
      and .head_sha == $revision
      and (.status | type == "string")
      and (.conclusion == null or (.conclusion | type == "string"))
      and (.app | type == "object")
      and (.app.slug | type == "string"))
  ' "$checks" >/dev/null; then
  echo "default-branch check evidence is malformed or exceeds bounds" >&2
  exit 1
fi

required_checks=(
  "Deterministic simulation change gate"
  "Deterministic simulation contracts and corpus"
)
for required_check in "${required_checks[@]}"; do
  if ! jq -e \
    --arg name "$required_check" \
    --arg revision "$revision" '
      [.check_runs[] | select(.name == $name)]
      | length == 1
        and .[0].head_sha == $revision
        and .[0].status == "completed"
        and .[0].conclusion == "success"
        and .[0].app.slug == "github-actions"
    ' "$checks" >/dev/null; then
    printf 'required simulation check is absent, duplicated, or unsuccessful: %s\n' \
      "$required_check" >&2
    exit 1
  fi
done

mapfile -d '' metadata_files < <(
  find "$corpus" -mindepth 2 -maxdepth 2 -type f -name metadata.json -print0 | sort -z
)
if ((${#metadata_files[@]} == 0 || ${#metadata_files[@]} > maximum_entries)); then
  echo "simulation corpus entry count is empty or exceeds bounds" >&2
  exit 1
fi

matching_metadata=()
for metadata in "${metadata_files[@]}"; do
  if (( $(stat -c %s "$metadata") > maximum_metadata_bytes )); then
    printf 'simulation corpus metadata exceeds its byte bound: %s\n' "$metadata" >&2
    exit 1
  fi
  if jq -e --arg issue "$issue_url" '.issue == $issue' "$metadata" >/dev/null 2>&1; then
    matching_metadata+=("$metadata")
  fi
done
if ((${#matching_metadata[@]} != 1)); then
  echo "closed issue must be linked by exactly one corpus entry" >&2
  exit 1
fi

metadata=${matching_metadata[0]}
if ! jq -e \
  --arg issue "$issue_url" \
  --arg signature "$signature_digest" '
    type == "object"
    and .schema_version == 2
    and (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,127}$"))
    and .scenario_file == "scenario.json"
    and .review_state == "reviewed"
    and .issue == $issue
    and (.promotion | type == "object")
    and (.promotion | keys | sort) == [
      "minimization",
      "minimized_scenario_sha256",
      "replay",
      "signature_digest",
      "source_revision",
      "workflow_run_id"
    ]
    and .promotion.signature_digest == $signature
    and (.promotion.minimized_scenario_sha256
      | type == "string" and test("^[0-9a-f]{64}$"))
    and (.promotion.source_revision | type == "string" and test("^[0-9a-f]{40}$"))
    and (.promotion.workflow_run_id | type == "number" and . > 0 and floor == .)
    and .promotion.replay == "confirmed_exact"
    and .promotion.minimization == "signature_preserving"
  ' "$metadata" >/dev/null; then
  echo "linked corpus metadata lacks reviewed signature-preserving promotion evidence" >&2
  exit 1
fi

promotion_source_revision=$(jq -er '.promotion.source_revision' "$metadata")
promotion_workflow_run_id=$(jq -er '.promotion.workflow_run_id' "$metadata")
expected_scenario_sha256=$(jq -er '.promotion.minimized_scenario_sha256' "$metadata")
if ! jq -e \
  --arg source_revision "$promotion_source_revision" \
  --arg scenario_sha256 "$expected_scenario_sha256" \
  --argjson workflow_run_id "$promotion_workflow_run_id" '
    .issue.body
    | contains("- Source revision: `" + $source_revision + "`")
      and contains("- Workflow run: `" + ($workflow_run_id | tostring) + "`")
      and contains("- Minimized scenario SHA-256: `" + $scenario_sha256 + "`")
  ' "$event" >/dev/null; then
  echo "linked corpus promotion provenance does not match the tracked issue" >&2
  exit 1
fi

entry_directory=$(dirname "$metadata")
scenario="$entry_directory/scenario.json"
if [[ ! -f "$scenario" || -L "$scenario" \
      || $(stat -c %s "$scenario") -gt $maximum_scenario_bytes ]]; then
  echo "linked minimized corpus scenario is missing or exceeds bounds" >&2
  exit 1
fi
actual_scenario_sha256=$(sha256sum "$scenario" | cut -d' ' -f1)
if [[ "$actual_scenario_sha256" != "$expected_scenario_sha256" ]]; then
  echo "linked minimized corpus scenario digest does not match promotion evidence" >&2
  exit 1
fi

if ! "$sim_bin" corpus test "$corpus"; then
  echo "reviewed simulation corpus did not pass on the default-branch revision" >&2
  exit 1
fi

corpus_entry=$(jq -er '.id' "$metadata")
mkdir -p "$(dirname "$output")"
temporary="$output.tmp.$$"
trap 'rm -f "$temporary"' EXIT
jq -n \
  --argjson issue_number "$issue_number" \
  --arg corpus_entry "$corpus_entry" \
  --arg signature_digest "$signature_digest" \
  --arg scenario_sha256 "$actual_scenario_sha256" \
  --arg revision "$revision" \
  --arg first_check "${required_checks[0]}" \
  --arg second_check "${required_checks[1]}" \
  '{
    schema_version: 1,
    status: "closure_accepted",
    issue_number: $issue_number,
    corpus_entry: $corpus_entry,
    signature_digest: $signature_digest,
    minimized_scenario_sha256: $scenario_sha256,
    revision: $revision,
    required_checks: [$first_check, $second_check]
  }' >"$temporary"
mv "$temporary" "$output"
trap - EXIT
