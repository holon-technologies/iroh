#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries include literal workflow expressions.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/release.yml"

required=(
  'simulation_release_readiness:'
  'name: Require simulation release evidence'
  'needs: preflight'
  'timeout-minutes: 10'
  'runs-on: ubuntu-latest'
  'actions: read'
  'checks: read'
  'issues: read'
  'scripts/check-simulation-release-readiness.sh'
  '--repository "${{ github.repository }}"'
  '--revision "${{ needs.preflight.outputs.base_hash }}"'
  '--policy krikos-sim/operations-policy.json'
  'simulation-release-readiness-${{ github.run_id }}'
  'if-no-files-found: error'
  'retention-days: 14'
  'Propagate simulation release readiness'
  'needs: [preflight, simulation_release_readiness]'
)
for expected in "${required[@]}"; do
  if ! grep -Fq -- "$expected" "$workflow"; then
    printf 'release workflow is missing simulation evidence contract: %s\n' "$expected" >&2
    exit 1
  fi
done

readiness_job=$(sed -n '/^  simulation_release_readiness:/,/^  build_release:/p' "$workflow")
if grep -Fq -- 'continue-on-error: true' <<<"$readiness_job"; then
  echo "release readiness must not mask evidence failures" >&2
  exit 1
fi

check_line=$(grep -n -m1 'scripts/check-simulation-release-readiness.sh' "$workflow" | cut -d: -f1)
upload_line=$(grep -n -m1 'simulation-release-readiness-${{ github.run_id }}' "$workflow" | cut -d: -f1)
propagate_line=$(grep -n -m1 'Propagate simulation release readiness' "$workflow" | cut -d: -f1)
build_line=$(grep -n -m1 '^  build_release:' "$workflow" | cut -d: -f1)
if ((check_line >= upload_line || upload_line >= propagate_line || propagate_line >= build_line)); then
  echo "release evidence check, publication, propagation, and build must remain ordered" >&2
  exit 1
fi

echo "simulation release workflow contract passed"
