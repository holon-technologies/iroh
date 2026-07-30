#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries include literal workflow expressions.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/ci.yml"

required=(
  'simulation_contracts:'
  'name: Deterministic simulation contracts and corpus'
  'simulation_gate:'
  'name: Deterministic simulation change gate'
  "timeout-minutes: \${{ github.event_name == 'push' && 30 || 15 }}"
  'fetch-depth: 0'
  'scripts/select-simulation-gate.sh'
  '--base-revision "$BASE_REVISION"'
  '--candidate-revision "$CANDIDATE_REVISION"'
  '--tier "$GATE_TIER"'
  '--impact-policy krikos-sim/change-impact-policy.json'
  '--coverage-policy krikos-sim/coverage-policy.json'
  'scripts/run-simulation-gate.sh'
  'cargo-sim corpus test krikos-sim/corpus'
  'Propagate deterministic gate result'
  'retention-days: 14'
)
for text in "${required[@]}"; do
  if ! grep -Fq -- "$text" "$workflow"; then
    printf 'simulation gate workflow is missing required contract: %s\n' "$text" >&2
    exit 1
  fi
done

gate_job=$(sed -n '/^  simulation_gate:/,/^  cross_build:/p' "$workflow")
if grep -Eq -- '--seeds ["'\'']?[0-9]+\.\.[0-9]+' <<<"$gate_job"; then
  echo "change gate must not contain fixed exploratory seed ranges" >&2
  exit 1
fi
# continue-on-error is forbidden everywhere in the change gate except on the
# sccache install step: a cache-service outage must not fail a required gate,
# but that step never runs gate assertions, so allowing it there cannot mask
# a real failure. The exemption is keyed to the sccache action reference
# (stable across Dependabot SHA bumps) rather than a step name, which could
# be renamed without anyone noticing the contract had gone stale.
if awk '
  BEGIN { in_step = 0; is_sccache = 0; has_coe = 0; bad = 0 }
  /^      - / {
    if (in_step && has_coe && !is_sccache) { bad = 1 }
    in_step = 1; is_sccache = 0; has_coe = 0
  }
  /uses: mozilla-actions\/sccache-action@/ { is_sccache = 1 }
  /continue-on-error: true/ { has_coe = 1 }
  END {
    if (in_step && has_coe && !is_sccache) { bad = 1 }
    exit (bad ? 0 : 1)
  }
' <<<"$gate_job"; then
  echo "change gate must not mask failures with continue-on-error outside the sccache install step" >&2
  exit 1
fi

upload_line=$(grep -n -m1 'Upload deterministic gate evidence' "$workflow" | cut -d: -f1)
propagate_line=$(grep -n -m1 'Propagate deterministic gate result' "$workflow" | cut -d: -f1)
if ((upload_line >= propagate_line)); then
  echo "deterministic gate result must be propagated after evidence upload" >&2
  exit 1
fi

echo "deterministic simulation change gate workflow contract passed"
