#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries include literal workflow expressions.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/simulation-nightly.yml"

if [[ ! -f "$workflow" ]]; then
  printf '%s\n' 'deterministic simulation nightly workflow is missing' >&2
  exit 1
fi

quoted_seed_count=$(grep -Ec '^[[:space:]]+seed: "[0-9a-f]{64}"[[:space:]]*$' "$workflow" || true)
if ((quoted_seed_count != 5)); then
  printf 'nightly replay matrix must contain five quoted 64-hex seeds; found %d\n' \
    "$quoted_seed_count" >&2
  exit 1
fi

if grep -Eq '^[[:space:]]+seed: [0-9a-f]{64}[[:space:]]*$' "$workflow"; then
  printf '%s\n' 'nightly replay matrix contains a YAML-coercible unquoted seed' >&2
  exit 1
fi

required=(
  'mkdir -p "$RUNNER_TEMP/${{ matrix.scenario }}"'
  'environment.txt'
  '--seed "${{ matrix.seed }}"'
  'if: always()'
  'if-no-files-found: error'
  'resource_exhaustion:'
  'RESOURCE_SEED: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
  'iroh-sim/corpus/resource-${{ matrix.resource }}-limit/scenario.json'
  '$RUNNER_TEMP/resource-${{ matrix.resource }}/manifest.json'
  'retention-days: 14'
)

for expected in "${required[@]}"; do
  if ! grep -Fq -- "$expected" "$workflow"; then
    printf 'nightly workflow is missing required contract: %s\n' "$expected" >&2
    exit 1
  fi
done

for resource in connection relay socket stream timer trace; do
  if ! grep -Fq -- "resource: $resource" "$workflow"; then
    printf 'nightly resource matrix is missing: %s\n' "$resource" >&2
    exit 1
  fi
done

prepare_line=$(grep -n -m1 'mkdir -p "$RUNNER_TEMP/${{ matrix.scenario }}"' "$workflow" | cut -d: -f1)
run_line=$(grep -n -m1 'name: Run named scenario' "$workflow" | cut -d: -f1)
if ((prepare_line >= run_line)); then
  printf '%s\n' 'nightly diagnostic root must be prepared before scenario execution' >&2
  exit 1
fi

printf '%s\n' 'deterministic simulation nightly workflow contract passed'
