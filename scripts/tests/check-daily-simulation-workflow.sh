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
  '- cron: "23 1,7,13,19 * * *"'
  'workflow_dispatch:'
  'permissions:'
  'contents: read'
  'actions: read'
  'issues: write'
  'group: iroh-daily-simulation-soak'
  'cancel-in-progress: false'
  'build_simulator:'
  'soak_lane:'
  'aggregate:'
  'runs-on: ubuntu-latest'
  'timeout-minutes: 300'
  'cargo build --release --manifest-path iroh-sim/Cargo.toml --bin cargo-sim'
  'name: iroh-sim-cargo-sim-${{ github.sha }}'
  'retention-days: 1'
  'needs: build_simulator'
  'fail-fast: false'
  'max-parallel: 12'
  'actions/download-artifact@v8'
  'sha256sum --check cargo-sim.sha256'
  'seed_window=$((RUN_NUMBER * 16 + LANE_INDEX))'
  'scripts/run-daily-simulation-soak.sh'
  '--lane "${{ matrix.lane }}"'
  '--seed-window "$seed_window"'
  '--artifacts "$RUNNER_TEMP/daily-soak"'
  '--sim-bin "$RUNNER_TEMP/cargo-sim/cargo-sim"'
  '--max-runs-per-epoch 10416'
  'pattern: iroh-sim-soak-*-${{ github.run_id }}'
  'scripts/aggregate-daily-simulation-soak.sh'
  '--source-revision "${{ github.sha }}"'
  '--workflow-run-id "${{ github.run_id }}"'
  '--observed-at-unix-secs "$observed_at"'
  'scripts/collect-simulation-coverage-history.sh'
  'scripts/merge-simulation-coverage-history.sh'
  'scripts/select-simulation-gaps.sh'
  'scripts/triage-simulation-failures.sh'
  'scripts/upsert-simulation-issues.sh'
  'iroh-sim-soak-triage-${{ github.run_id }}'
  'GH_TOKEN: ${{ github.token }}'
  'daily-soak-aggregate.json'
  'rolling-coverage.json'
  'gap-selection.json'
  'GH_TOKEN: ${{ github.token }}'
  'actions/upload-artifact@v7'
  'if-no-files-found: error'
  'retention-days: 14'
  'if: always()'
  'Propagate lane result'
  'Propagate aggregate result'
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

expected_lanes=(
  direct/deterministic-test
  direct/production-provider
  discovery/deterministic-test
  discovery/production-provider
  impairment/deterministic-test
  impairment/production-provider
  mobility/deterministic-test
  mobility/production-provider
  nat/deterministic-test
  nat/production-provider
  ready-order/deterministic-test
  ready-order/production-provider
  relay/deterministic-test
  relay/production-provider
)
mapfile -t actual_lanes < <(
  sed -n 's/^[[:space:]]*- lane: \([^[:space:]]*\)$/\1/p' "$workflow"
)
if [[ "${actual_lanes[*]}" != "${expected_lanes[*]}" ]]; then
  echo "daily simulation matrix must contain the exact fourteen soak lanes in plan order" >&2
  exit 1
fi

expected_indexes=(0 1 2 3 4 5 6 7 8 9 10 11 12 13)
mapfile -t actual_indexes < <(
  sed -n 's/^[[:space:]]*lane_index: \([0-9][0-9]*\)$/\1/p' "$workflow"
)
if [[ "${actual_indexes[*]}" != "${expected_indexes[*]}" ]]; then
  echo "daily simulation matrix must assign exact unique lane indexes 0 through 13" >&2
  exit 1
fi

lane_upload_line=$(grep -n -m1 'Upload lane report and failure artifacts' "$workflow" | cut -d: -f1)
lane_propagate_line=$(grep -n -m1 'Propagate lane result' "$workflow" | cut -d: -f1)
aggregate_upload_line=$(grep -n -m1 'Upload aggregate report' "$workflow" | cut -d: -f1)
aggregate_propagate_line=$(grep -n -m1 'Propagate aggregate result' "$workflow" | cut -d: -f1)
history_line=$(grep -n -m1 'scripts/collect-simulation-coverage-history.sh' "$workflow" | cut -d: -f1)
rolling_line=$(grep -n -m1 'scripts/merge-simulation-coverage-history.sh' "$workflow" | cut -d: -f1)
selection_line=$(grep -n -m1 'scripts/select-simulation-gaps.sh' "$workflow" | cut -d: -f1)
if ((lane_upload_line >= lane_propagate_line)); then
  echo "lane result must be propagated only after artifact upload" >&2
  exit 1
fi
if ((aggregate_upload_line >= aggregate_propagate_line)); then
  echo "aggregate result must be propagated only after artifact upload" >&2
  exit 1
fi
if ((history_line >= rolling_line || rolling_line >= selection_line)); then
  echo "history collection, rolling merge, and gap selection must remain ordered" >&2
  exit 1
fi

echo "daily simulation soak workflow contract passed"
