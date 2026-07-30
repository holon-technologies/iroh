#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/resource-canary.yml"

if [[ ! -f "$workflow" ]]; then
  echo "production resource canary workflow is missing" >&2
  exit 1
fi

required=(
  'schedule:'
  'workflow_dispatch:'
  'name: GitHub-hosted 50%-scale resource observation'
  'runs-on: ubuntu-latest'
  'timeout-minutes: 90'
  'cargo build --profile optimized-release -p krikos-bench'
  '--features resource-canary --bin resource-canary'
  'target/optimized-release/resource-canary preflight'
  '--host-profile github-hosted-standard'
  'target/optimized-release/resource-canary run --host-profile github-hosted-standard'
  '--lane all --scale-percent 50'
  '--warmup-seconds 30 --measurement-seconds 300 --cooldown-seconds 30'
  '--sample-interval-seconds 1 --baseline-seconds 5'
  'if: always()'
  'retention-days: 30'
)

for expected in "${required[@]}"; do
  if ! grep -Fq -- "$expected" "$workflow"; then
    echo "resource canary workflow is missing required contract: $expected" >&2
    exit 1
  fi
done

if grep -Eq '^[[:space:]]+pull_request:' "$workflow"; then
  echo "production resource canary must not run as a pull-request host-performance gate" >&2
  exit 1
fi

if grep -Fq -- 'self-hosted' "$workflow"; then
  echo "scheduled resource observations must use free GitHub-hosted capacity" >&2
  exit 1
fi

if grep -Fq -- '--scale-percent 100' "$workflow"; then
  echo "the underqualified GitHub host must not claim the production evidence profile" >&2
  exit 1
fi

echo "GitHub-hosted resource observation workflow contract passed"
