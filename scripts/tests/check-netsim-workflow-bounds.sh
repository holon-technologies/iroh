#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
entry="$repo_root/.github/workflows/netsim.yml"
runner="$repo_root/.github/workflows/netsim_runner.yaml"
ci="$repo_root/.github/workflows/ci.yml"

for required in \
  'group: iroh-netsim-${{ github.ref || inputs.iroh_ref }}' \
  'cancel-in-progress: false'; do
  grep -Fq -- "$required" "$entry" || {
    printf 'Netsim entry workflow is missing bound: %s\n' "$required" >&2
    exit 1
  }
done

for required in \
  'timeout-minutes: 45' \
  'NETSIM_TIMEOUT: 10m' \
  'timeout --kill-after=30s "$NETSIM_TIMEOUT"' \
  'scripts/validate_netsim_reports.py' \
  'maximum_cases=64' \
  'MAX_WORKERS < 1 || MAX_WORKERS > 6' \
  '${#sim_paths[@]} > 3' \
  '^sims/(iroh|integration|paused)(/[a-z0-9_]+\.json)?$' \
  'if [[ -f "../chuck/netsim/$sim_path" ]]; then' \
  'retention-days: 3' \
  '- name: Cleanup' \
  'if: always()'; do
  grep -Fq -- "$required" "$runner" || {
    printf 'Netsim runner is missing execution bound: %s\n' "$required" >&2
    exit 1
  }
done

grep -Fq -- "sims/iroh/iroh.json,sims/integration" "$ci" || {
  printf 'Main CI is missing its bounded Netsim selection\n' >&2
  exit 1
}

python3 - "$entry" "$runner" "$ci" <<'PY'
import pathlib
import sys
import yaml

for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    if not isinstance(yaml.safe_load(path.read_text()), dict):
        raise SystemExit(f"workflow is not a mapping: {path}")
PY

PYTHONDONTWRITEBYTECODE=1 \
  python3 "$repo_root/scripts/tests/test_validate_netsim_reports.py"

echo "Netsim workflow bounds contract passed"
