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
  'runs-on: [self-hosted, linux, X64, iroh-resource-canary]'
  'timeout-minutes: 90'
  'cargo build --profile optimized-release -p iroh-bench'
  '--features resource-canary --bin resource-canary'
  'target/optimized-release/resource-canary preflight'
  'target/optimized-release/resource-canary run --lane all --scale-percent 100'
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

echo "production resource canary workflow contract passed"
