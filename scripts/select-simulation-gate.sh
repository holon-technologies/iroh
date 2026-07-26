#!/usr/bin/env bash

set -euo pipefail

base_revision=
candidate_revision=
tier=
impact_policy=
coverage_policy=
sim_bin=
output=

usage() {
  printf '%s\n' \
    'Usage: select-simulation-gate.sh --base-revision HEX --candidate-revision HEX --tier pull-request|main --impact-policy PATH --coverage-policy PATH [--sim-bin PATH] --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --base-revision)
      base_revision=$2
      shift 2
      ;;
    --candidate-revision)
      candidate_revision=$2
      shift 2
      ;;
    --tier)
      tier=$2
      shift 2
      ;;
    --impact-policy)
      impact_policy=$2
      shift 2
      ;;
    --coverage-policy)
      coverage_policy=$2
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
      printf 'unknown simulation gate selector argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$base_revision" || -z "$candidate_revision" || -z "$tier" \
      || -z "$impact_policy" || -z "$coverage_policy" || -z "$output" ]]; then
  echo "all required simulation gate selector arguments must be provided" >&2
  usage >&2
  exit 64
fi
for revision_name in base_revision candidate_revision; do
  revision=${!revision_name}
  if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    printf -- '--%s must be exactly 40 lowercase hexadecimal characters\n' \
      "${revision_name//_/-}" >&2
    exit 64
  fi
done
if [[ "$tier" != pull-request && "$tier" != main ]]; then
  echo "--tier must be pull-request or main" >&2
  exit 64
fi
for policy in "$impact_policy" "$coverage_policy"; do
  if [[ ! -f "$policy" || -L "$policy" ]]; then
    printf 'simulation gate policy is missing or unsafe: %s\n' "$policy" >&2
    exit 66
  fi
done
if [[ -n "$sim_bin" && ! -x "$sim_bin" ]]; then
  printf 'simulation gate binary is not executable: %s\n' "$sim_bin" >&2
  exit 66
fi
if ! git cat-file -e "${candidate_revision}^{commit}" 2>/dev/null; then
  echo "candidate revision is not available in the local Git repository" >&2
  exit 65
fi

if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
mkdir -p "$(dirname "$output")"
scratch_root=$(mktemp -d)
trap 'rm -rf "$scratch_root"' EXIT
forward="$scratch_root/forward.paths"
reverse="$scratch_root/reverse.paths"
paths_jsonl="$scratch_root/paths.jsonl"
changes="$scratch_root/changes.json"
: >"$paths_jsonl"
diff_available=true

if ! git cat-file -e "${base_revision}^{commit}" 2>/dev/null; then
  diff_available=false
elif [[ "$base_revision" != "$candidate_revision" ]]; then
  if ! git diff --name-only -z --find-renames \
    "$base_revision" "$candidate_revision" -- >"$forward"; then
    diff_available=false
  fi
  if [[ "$diff_available" == true ]] \
    && ! git diff --name-only -z --find-renames \
      "$candidate_revision" "$base_revision" -- >"$reverse"; then
    diff_available=false
  fi
  if [[ "$diff_available" == true ]]; then
    path_count=0
    for path_file in "$forward" "$reverse"; do
      while IFS= read -r -d '' path; do
        path_count=$((path_count + 1))
        if ((path_count > 4096)); then
          diff_available=false
          break 2
        fi
        jq -cn --arg path "$path" '$path' >>"$paths_jsonl"
      done <"$path_file"
    done
  fi
fi

if [[ "$diff_available" == true ]]; then
  jq -s 'sort | unique' "$paths_jsonl" >"$changes"
else
  printf '%s\n' '[]' >"$changes"
fi

command_args=(
  gate-select
  --impact-policy "$impact_policy"
  --coverage-policy "$coverage_policy"
  --base-revision "$base_revision"
  --candidate-revision "$candidate_revision"
  --tier "$tier"
  --changes "$changes"
  --output "$output"
)
if [[ "$diff_available" != true ]]; then
  command_args+=(--diff-unavailable)
fi

if [[ -n "$sim_bin" ]]; then
  "$sim_bin" "${command_args[@]}"
else
  repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  cargo run --quiet \
    --manifest-path "$repo_root/iroh-sim/Cargo.toml" \
    --bin cargo-sim -- \
    "${command_args[@]}"
fi
