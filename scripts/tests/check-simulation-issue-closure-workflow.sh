#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries include literal workflow expressions.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/simulation-issue-closure.yml"

if [[ ! -f "$workflow" ]]; then
  echo "simulation issue closure workflow is missing" >&2
  exit 1
fi

# Third-party actions are pinned to a commit SHA with a trailing `# <ref>`
# comment (e.g. `actions/checkout@<40-hex>  # v7`). Normalize that back to
# `actions/checkout@v7` before matching contract literals below, so this
# check asserts on the human-readable ref rather than a SHA that Dependabot
# will rotate on every bump.
normalized_workflow=$(mktemp)
trap 'rm -f "$normalized_workflow"' EXIT
sed -E 's/@[0-9a-f]{40}[[:space:]]+#[[:space:]]*([^[:space:]]+)/@\1/' "$workflow" > "$normalized_workflow"
workflow="$normalized_workflow"

required=(
  'name: Simulation Issue Closure Guard'
  'issues:'
  'types: [closed]'
  'contents: read'
  'checks: read'
  'issues: write'
  'runs-on: ubuntu-latest'
  'timeout-minutes: 20'
  'contains(github.event.issue.labels.*.name, '\''simulation'\'')'
  'actions/checkout@v7'
  'github.event.repository.default_branch'
  'cargo build --release --manifest-path iroh-sim/Cargo.toml --bin cargo-sim'
  'commits/$revision/check-runs?per_page=100'
  'scripts/check-simulation-issue-closure.sh'
  '--event "$GITHUB_EVENT_PATH"'
  '--repository "${{ github.repository }}"'
  '--revision "$revision"'
  '--corpus iroh-sim/corpus'
  '--checks "$RUNNER_TEMP/check-runs.json"'
  '--sim-bin iroh-sim/target/release/cargo-sim'
  'gh issue reopen "${{ github.event.issue.number }}"'
  'retention-days: 14'
  'Propagate closure guard result'
)
for expected in "${required[@]}"; do
  if ! grep -Fq -- "$expected" "$workflow"; then
    printf 'simulation issue closure workflow is missing required contract: %s\n' \
      "$expected" >&2
    exit 1
  fi
done

if grep -Eq '^[[:space:]]+pull_request_target:' "$workflow"; then
  echo "simulation issue closure guard must not execute pull-request code with issue permission" >&2
  exit 1
fi
if grep -Fq 'self-hosted' "$workflow"; then
  echo "simulation issue closure guard must use GitHub-hosted infrastructure" >&2
  exit 1
fi

guard_line=$(grep -n -m1 'scripts/check-simulation-issue-closure.sh' "$workflow" | cut -d: -f1)
reopen_line=$(grep -n -m1 'gh issue reopen' "$workflow" | cut -d: -f1)
propagate_line=$(grep -n -m1 'Propagate closure guard result' "$workflow" | cut -d: -f1)
if ((guard_line >= reopen_line || reopen_line >= propagate_line)); then
  echo "closure guard, enforcement, and status propagation must remain ordered" >&2
  exit 1
fi

echo "simulation issue closure workflow contract passed"
