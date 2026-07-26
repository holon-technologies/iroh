#!/usr/bin/env bash

set -euo pipefail

records=
repository=
output=
maximum_records=16
maximum_search_results=100
maximum_record_bytes=131072
maximum_body_bytes=65536

usage() {
  printf '%s\n' \
    'Usage: upsert-simulation-issues.sh --records PATH --repository OWNER/REPO --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --records)
      records=$2
      shift 2
      ;;
    --repository)
      repository=$2
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
      printf 'unknown simulation issue upsert argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$records" || -z "$repository" || -z "$output" ]]; then
  echo "all simulation issue upsert arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! -d "$records" || -L "$records" \
      || ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "simulation issue upsert inputs are malformed or unsafe" >&2
  exit 66
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI is required for simulation issue upsert" >&2
  exit 2
fi
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
if [[ -e "$output" || -L "$output" ]]; then
  echo "simulation issue upsert output must not already exist" >&2
  exit 73
fi
mkdir -p "$(dirname "$output")"

if find "$records" -type l -print -quit | grep -q .; then
  echo "simulation issue records contain a symbolic link" >&2
  exit 2
fi
mapfile -d '' record_files < <(find "$records" -type f -name '*.json' -print0 | sort -z)
if ((${#record_files[@]} > maximum_records)); then
  echo "simulation issue record bound exceeded" >&2
  exit 2
fi

scratch_root=$(mktemp -d)
trap 'rm -rf "$scratch_root"' EXIT
actions="$scratch_root/actions.jsonl"
: >"$actions"

created=0
updated=0
reopened=0
declare -A seen_signatures=()
for index in "${!record_files[@]}"; do
  record=${record_files[$index]}
  if (( $(stat -c %s "$record") > maximum_record_bytes )) \
    || ! jq -e \
      --argjson maximum_body_bytes "$maximum_body_bytes" '
        . as $record
        | type == "object"
          and .schema_version == 1
          and .classification == "product_correctness"
          and (.signature_digest | type == "string" and test("^[0-9a-f]{64}$"))
          and (.minimized_scenario_sha256
            | type == "string" and test("^[0-9a-f]{64}$"))
          and (.title | type == "string" and length > 0 and length <= 180)
          and (.body | type == "string" and length > 0 and length <= $maximum_body_bytes)
          and (.body | contains("<!-- iroh-sim-signature:" + $record.signature_digest + " -->"))
          and (.body | contains(
            "- Minimized scenario SHA-256: `" + $record.minimized_scenario_sha256 + "`"
          ))
          and .labels == ["bug", "simulation"]
          and (.source_revision | type == "string" and test("^[0-9a-f]{40}$"))
          and (.workflow_run_id | type == "number" and . > 0 and floor == .)
          and (.lane | type == "string" and length > 0 and length <= 128)
          and (.seed_ordinal | type == "string" and test("^[0-9]+$"))
          and (.seed_lease | type == "object")
          and .replay == "confirmed_exact"
          and .minimization == "signature_preserving"
          and .corpus_status == "pending_promotion"
      ' "$record" >/dev/null; then
    printf 'simulation issue record is malformed: %s\n' "$record" >&2
    exit 2
  fi
  signature=$(jq -r '.signature_digest' "$record")
  if [[ -n "${seen_signatures[$signature]:-}" ]]; then
    echo "duplicate simulation issue signature in one workflow" >&2
    exit 2
  fi
  seen_signatures[$signature]=1
  marker="<!-- iroh-sim-signature:$signature -->"
  issue_candidates="$scratch_root/issues-$index.json"
  if ! gh issue list \
    --repo "$repository" \
    --state all \
    --search "$signature in:body" \
    --limit "$maximum_search_results" \
    --json number,state,title,body \
    >"$issue_candidates"; then
    echo "GitHub issue signature search failed" >&2
    exit 2
  fi
  if (( $(stat -c %s "$issue_candidates") > 8388608 )) \
    || ! jq -e \
      --argjson maximum "$maximum_search_results" '
        type == "array"
        and length < $maximum
        and all(.[];
          (.number | type == "number" and . > 0 and floor == .)
          and (.state == "OPEN" or .state == "CLOSED")
          and (.title | type == "string")
          and (.body | type == "string"))
        and ([.[].number] | unique | length) == length
      ' "$issue_candidates" >/dev/null; then
    echo "GitHub issue signature search is malformed, truncated, or exceeds bounds" >&2
    exit 2
  fi
  matches=$(jq -c \
    --arg marker "$marker" \
    '[.[] | select(.body | contains($marker))]' \
    "$issue_candidates")
  match_count=$(jq -r 'length' <<<"$matches")
  if ((match_count > 1)); then
    printf 'multiple GitHub issues contain simulation signature %s\n' "$signature" >&2
    exit 2
  fi

  title=$(jq -r '.title' "$record")
  body_file="$scratch_root/body-$index.md"
  jq -j '.body' "$record" >"$body_file"
  if ((match_count == 0)); then
    issue_url=$(gh issue create \
      --repo "$repository" \
      --title "$title" \
      --body-file "$body_file" \
      --label bug \
      --label simulation) || {
        echo "GitHub simulation issue creation failed" >&2
        exit 2
      }
    if [[ ! "$issue_url" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[0-9]+$ ]]; then
      echo "GitHub simulation issue creation returned an invalid URL" >&2
      exit 2
    fi
    created=$((created + 1))
    jq -cn --arg signature "$signature" --arg action created --arg issue "$issue_url" \
      '{signature: $signature, action: $action, issue: $issue}' >>"$actions"
  else
    issue_number=$(jq -r '.[0].number' <<<"$matches")
    issue_state=$(jq -r '.[0].state' <<<"$matches")
    if ! gh issue edit "$issue_number" \
      --repo "$repository" \
      --title "$title" \
      --body-file "$body_file" \
      --add-label bug \
      --add-label simulation \
      >/dev/null; then
      echo "GitHub simulation issue update failed" >&2
      exit 2
    fi
    updated=$((updated + 1))
    action=updated
    if [[ "$issue_state" == CLOSED ]]; then
      if ! gh issue reopen "$issue_number" --repo "$repository" >/dev/null; then
        echo "GitHub simulation issue reopen failed" >&2
        exit 2
      fi
      reopened=$((reopened + 1))
      action=reopened
    fi
    jq -cn \
      --arg signature "$signature" \
      --arg action "$action" \
      --argjson issue_number "$issue_number" \
      '{signature: $signature, action: $action, issue_number: $issue_number}' \
      >>"$actions"
  fi
done

jq -s \
  --argjson processed "${#record_files[@]}" \
  --argjson created "$created" \
  --argjson updated "$updated" \
  --argjson reopened "$reopened" \
  '{
    schema_version: 1,
    status: "success",
    processed: $processed,
    created: $created,
    updated: $updated,
    reopened: $reopened,
    actions: .
  }' "$actions" >"$output"
