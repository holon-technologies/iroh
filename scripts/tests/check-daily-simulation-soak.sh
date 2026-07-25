#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries are literal shell-source contracts.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner="$repo_root/scripts/run-daily-simulation-soak.sh"

if [[ ! -f "$runner" ]]; then
  echo "daily simulation soak runner is missing" >&2
  exit 1
fi

bash -n "$runner"

required=(
  'epochs=8'
  'epoch_seconds=1800'
  'jobs=4'
  'batch_runs=64'
  'max_runs_per_epoch=125000'
  'max_failure_artifacts_per_epoch=2'
  'max_artifact_bytes_per_epoch=33554432'
  '"$sim_bin" soak'
  '--plan "$plan"'
  '--seed-window "$seed_window"'
  '--max-failure-artifacts "$max_failure_artifacts_per_epoch"'
  '--max-artifact-bytes "$max_artifact_bytes_per_epoch"'
  'daily-soak-summary.json'
  'GITHUB_STEP_SUMMARY'
)

for expected in "${required[@]}"; do
  if ! grep -Fq -- "$expected" "$runner"; then
    echo "daily simulation soak runner is missing required contract: $expected" >&2
    exit 1
  fi
done

if grep -Eq '(^|[[:space:]])&[[:space:]]*($|#)' "$runner"; then
  echo "daily simulation epochs must execute sequentially" >&2
  exit 1
fi

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
fake_sim="$fixture_root/fake-cargo-sim"
cat >"$fake_sim" <<'FAKE_SIM'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == "soak" ]]
shift
artifact_root=
epoch=
while (($# > 0)); do
  case "$1" in
    --artifacts)
      artifact_root=$2
      shift 2
      ;;
    --epoch)
      epoch=$2
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$artifact_root"
failed=0
status=0
if [[ "$epoch" == "1" ]]; then
  failed=1
  status=74
fi
jq -n \
  --argjson epoch "$epoch" \
  --argjson failed "$failed" \
  '{
    schema_version: 1,
    epoch: $epoch,
    completed_runs: 1,
    successful_runs: (1 - $failed),
    failed_runs: $failed,
    errored_runs: 0,
    worker_panics: 0,
    failure_artifacts: {
      retained: $failed,
      omitted: 0,
      retained_bytes: (128 * $failed),
      infrastructure_error: null
    },
    unique_failures: []
  }' >"$artifact_root/.soak-summary.json.tmp"
mv "$artifact_root/.soak-summary.json.tmp" "$artifact_root/soak-summary.json"
exit "$status"
FAKE_SIM
chmod +x "$fake_sim"

artifact_root="$fixture_root/artifacts"
set +e
"$runner" \
  --seed-window 42 \
  --artifacts "$artifact_root" \
  --sim-bin "$fake_sim" \
  --epochs 2 \
  --epoch-seconds 1 \
  --jobs 1 \
  --batch-runs 1 \
  --max-runs-per-epoch 1
runner_status=$?
set -e

if [[ "$runner_status" -ne 1 ]]; then
  echo "daily runner must report a simulation failure after completing all epochs" >&2
  exit 1
fi

report="$artifact_root/daily-soak-summary.json"
jq -e '
  .status == "simulation_failure"
  and .configured_epochs == 2
  and .completed_epochs == 2
  and .totals.completed_runs == 2
  and .totals.successful_runs == 1
  and .totals.failed_runs == 1
  and .totals.errored_runs == 0
  and (.epochs | length) == 2
' "$report" >/dev/null

echo "daily simulation soak runner contract passed"
