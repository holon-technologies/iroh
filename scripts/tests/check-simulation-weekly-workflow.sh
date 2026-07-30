#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries include literal workflow expressions.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/simulation-weekly.yml"

required=(
  'name: Deterministic Simulation Weekly Service'
  'group: krikos-deterministic-simulation-weekly'
  'cancel-in-progress: false'
  'service_contract:'
  'performance_correlation:'
  'gate_runtime_slo:'
  'name: Audit PR and main simulation P95 runtime'
  'actions: read'
  'scripts/audit-simulation-gate-runtime-slo.sh'
  '--policy krikos-sim/operations-policy.json'
  'krikos-sim-gate-runtime-slo-${{ github.run_id }}'
  'Propagate simulation gate runtime SLO'
  'cargo-sim -- corpus test krikos-sim/corpus'
  'parity export public'
  'parity compare'
  'timeout-minutes: 60'
  'path: krikos-sim/target/criterion'
  'retention-days: 30'
)
for text in "${required[@]}"; do
  if ! grep -Fq -- "$text" "$workflow"; then
    printf 'weekly simulation workflow is missing required contract: %s\n' "$text" >&2
    exit 1
  fi
done

if grep -Eq '^[[:space:]]{2}schedule_soak:' "$workflow"; then
  echo "weekly workflow must not duplicate continuous deterministic exploration" >&2
  exit 1
fi
if grep -Eq -- '--seeds ["'\'']?[0-9]+\.\.[0-9]+' "$workflow"; then
  echo "weekly workflow must not contain fixed exploratory seed ranges" >&2
  exit 1
fi

echo "deterministic simulation weekly role contract passed"
