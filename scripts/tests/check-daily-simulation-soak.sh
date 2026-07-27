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
  '--lane'
  '"$sim_bin" soak'
  '--plan "$plan"'
  '--lane "$lane"'
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
selected_plan=
selected_lane=
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
    --plan)
      selected_plan=$2
      shift 2
      ;;
    --lane)
      selected_lane=$2
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "${EXPECTED_LANE:-}" ]]; then
  [[ "$selected_lane" == "$EXPECTED_LANE" ]]
  jq -e \
    --arg lane "$EXPECTED_LANE" \
    '.lanes | length == 14 and any(.[]; .id == $lane)' \
    "$selected_plan" >/dev/null
fi
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
  --arg lane "${selected_lane:-direct/deterministic-test}" \
  '{
    schema_version: 2,
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
    coverage: {
      schema_version: 2,
      policy_id: "iroh-network-modes-v1",
      policy_blake3: "8e275709a3bb949f570c51abf184e023bb8a618f3d8aa8cbbfa737d9cdfe52c2",
      rolling_window_days: 7,
      completed_runs: 1,
      observed_individuals: [],
      missing_individuals: [],
      observed_pairs: [],
      missing_pairs: [],
      observed_higher_order: [],
      missing_higher_order: [],
      observed_transitions: [],
      missing_transitions: [],
      observed_oracles: [],
      missing_oracles: [],
      observed_phases: [],
      missing_phases: [],
      known_gaps: []
    },
    seed_leases: [{
      schema_version: 2,
      policy_blake3: "8e275709a3bb949f570c51abf184e023bb8a618f3d8aa8cbbfa737d9cdfe52c2",
      plan_blake3: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      lane_id: $lane,
      seed_window: 42,
      epoch: $epoch,
      lane_index: 0,
      seed_start: ($epoch * 1000000),
      seed_end_exclusive: (($epoch + 1) * 1000000),
      consumed_runs: 1
    }],
    unique_failures: []
  }' >"$artifact_root/.soak-summary.json.tmp"
mv "$artifact_root/.soak-summary.json.tmp" "$artifact_root/soak-summary.json"
exit "$status"
FAKE_SIM
chmod +x "$fake_sim"

artifact_root="$fixture_root/artifacts"
set +e
EXPECTED_LANE=direct/deterministic-test "$runner" \
  --lane direct/deterministic-test \
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
  and .lane == "direct/deterministic-test"
  and .max_runs_per_epoch == 1
  and .configured_max_runs == 2
  and .configured_epochs == 2
  and .completed_epochs == 2
  and .totals.completed_runs == 2
  and .totals.successful_runs == 1
  and .totals.failed_runs == 1
  and .totals.errored_runs == 0
  and .coverage.policy_id == "iroh-network-modes-v1"
  and .coverage.completed_runs == 2
  and (.seed_leases | length) == 2
  and (.epochs | length) == 2
' "$report" >/dev/null

set +e
"$runner" \
  --lane missing/lane \
  --seed-window 43 \
  --artifacts "$fixture_root/unknown-lane-artifacts" \
  --sim-bin "$fake_sim" \
  --epochs 1 \
  --epoch-seconds 1 \
  --jobs 1 \
  --batch-runs 1 \
  --max-runs-per-epoch 1 >/dev/null 2>&1
unknown_lane_status=$?
set -e

if [[ "$unknown_lane_status" -ne 64 ]]; then
  echo "daily runner must reject a lane absent from the soak plan" >&2
  exit 1
fi
if [[ -e "$fixture_root/unknown-lane-artifacts" ]]; then
  echo "daily runner must validate the lane before creating artifacts" >&2
  exit 1
fi

compatibility_root="$fixture_root/compatibility-artifacts"
"$runner" \
  --seed-window 44 \
  --artifacts "$compatibility_root" \
  --sim-bin "$fake_sim" \
  --epochs 1 \
  --epoch-seconds 1 \
  --jobs 1 \
  --batch-runs 1 \
  --max-runs-per-epoch 1
jq -e '
  .status == "success"
  and .lane == null
  and .configured_max_runs == 1
' "$compatibility_root/daily-soak-summary.json" >/dev/null

echo "daily simulation soak runner contract passed"
