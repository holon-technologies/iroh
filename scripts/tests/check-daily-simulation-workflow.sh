#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries are literal workflow expressions.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/simulation-daily-soak.yml"

if [[ ! -f "$workflow" ]]; then
  echo "daily simulation soak workflow is missing" >&2
  exit 1
fi

required=(
  'name: Daily Deterministic Simulation Soak'
  'schedule:'
  'workflow_dispatch:'
  'permissions:'
  'contents: read'
  'group: iroh-daily-simulation-soak'
  'cancel-in-progress: false'
  'runs-on: ubuntu-latest'
  'timeout-minutes: 300'
  'cargo build --release -p iroh-sim --bin cargo-sim'
  'scripts/run-daily-simulation-soak.sh'
  '--seed-window "${{ github.run_number }}"'
  '--artifacts "$RUNNER_TEMP/daily-soak"'
  '--sim-bin target/release/cargo-sim'
  'actions/upload-artifact@v7'
  'if-no-files-found: error'
  'retention-days: 14'
  'if: always()'
  'Propagate simulation result'
)

for expected in "${required[@]}"; do
  if ! grep -Fq -- "$expected" "$workflow"; then
    echo "daily simulation workflow is missing required contract: $expected" >&2
    exit 1
  fi
done

if grep -Eq '^[[:space:]]+pull_request:' "$workflow"; then
  echo "the four-hour soak must not run on pull requests" >&2
  exit 1
fi
if grep -Fq -- 'self-hosted' "$workflow"; then
  echo "the daily soak must use free GitHub-hosted capacity" >&2
  exit 1
fi
if grep -Eq 'ubuntu-(4|8|16|32|64)-core|larger-runner' "$workflow"; then
  echo "the daily soak must not require paid larger runners" >&2
  exit 1
fi

upload_line=$(grep -n -m1 'actions/upload-artifact@v7' "$workflow" | cut -d: -f1)
propagate_line=$(grep -n -m1 'Propagate simulation result' "$workflow" | cut -d: -f1)
if ((upload_line >= propagate_line)); then
  echo "daily soak result must be propagated only after artifact upload" >&2
  exit 1
fi

echo "daily simulation soak workflow contract passed"
