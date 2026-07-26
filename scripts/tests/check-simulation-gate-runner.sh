#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner="$repo_root/scripts/run-simulation-gate.sh"
sim_bin="$repo_root/iroh-sim/target/debug/cargo-sim"

if [[ ! -x "$runner" ]]; then
  echo "simulation gate runner is missing or not executable" >&2
  exit 1
fi
bash -n "$runner"
cargo build --quiet --manifest-path "$repo_root/iroh-sim/Cargo.toml" --bin cargo-sim

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
printf '%s\n' '[]' >"$fixture_root/changes.json"
"$sim_bin" gate-select \
  --impact-policy "$repo_root/iroh-sim/change-impact-policy.json" \
  --coverage-policy "$repo_root/iroh-sim/coverage-policy.json" \
  --base-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --candidate-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --tier pull-request \
  --changes "$fixture_root/changes.json" \
  --output "$fixture_root/selection.json" \
  >/dev/null

fake_bin="$fixture_root/fake-cargo-sim"
cat >"$fake_bin" <<'FAKE_SIM'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_SIM_LOG"
printf '\n' >>"$FAKE_SIM_LOG"
if [[ "$*" == *" --crypto production-provider "* && ! -e "$FAKE_SIM_ONCE" ]]; then
  : >"$FAKE_SIM_ONCE"
  if [[ "$FAKE_SIM_MODE" == "product" ]]; then
    artifact_root=
    seed_range=
    while (($# > 0)); do
      case "$1" in
        --artifacts)
          artifact_root=$2
          shift 2
          ;;
        --seeds)
          seed_range=$2
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    seed=${seed_range%%..*}
    mkdir -p "$artifact_root"
    jq -n --argjson seed "$seed" '{
      config: {
        seed_start: $seed,
        seed_end_exclusive: ($seed + 1),
        jobs: 2,
        fail_fast: false,
        max_runs: 1
      },
      template_inventory: {},
      results: [{
        seed: $seed,
        terminal: { terminal: "failure" },
        error: null,
        worker_panic: false
      }],
      unique_failures: [{}],
      stopped_early: false
    }' >"$artifact_root/campaign-summary.json"
  fi
  exit 74
fi
exit 0
FAKE_SIM
chmod +x "$fake_bin"
export FAKE_SIM_LOG="$fixture_root/fake.log"
export FAKE_SIM_ONCE="$fixture_root/failed-once"
export FAKE_SIM_MODE=product

set +e
"$runner" \
  --selection "$fixture_root/selection.json" \
  --sim-bin "$fake_bin" \
  --artifacts "$fixture_root/artifacts" \
  --jobs 2
runner_status=$?
set -e
if [[ "$runner_status" -ne 1 ]]; then
  echo "gate runner must classify a campaign failure as a product failure" >&2
  exit 1
fi
jq -e '
  .schema_version == 1
  and .status == "product_failure"
  and .configured_runs == 12
  and .completed_runs == 12
  and (.failures | length) == 1
  and .failures[0].classification == "product_correctness"
' "$fixture_root/artifacts/gate-summary.json" >/dev/null
if [[ $(wc -l <"$FAKE_SIM_LOG") -ne 12 ]]; then
  echo "gate runner must execute every bounded work item" >&2
  exit 1
fi
grep -Fq -- '--max-runs 1' "$FAKE_SIM_LOG"
grep -Fq -- '--continue-on-failure' "$FAKE_SIM_LOG"

# Exit 74 without typed campaign evidence is an execution/infrastructure error,
# not permission to manufacture a product-correctness failure.
rm "$FAKE_SIM_ONCE"
export FAKE_SIM_MODE=infrastructure
set +e
"$runner" \
  --selection "$fixture_root/selection.json" \
  --sim-bin "$fake_bin" \
  --artifacts "$fixture_root/infrastructure-artifacts" \
  --jobs 2
infrastructure_status=$?
set -e
if [[ "$infrastructure_status" -ne 2 ]]; then
  echo "gate runner must require typed campaign evidence for product failure" >&2
  exit 1
fi
jq -e '
  .status == "infrastructure_failure"
  and .product_failures == 0
  and .infrastructure_failures == 1
  and .failures[0].classification == "infrastructure"
' "$fixture_root/infrastructure-artifacts/gate-summary.json" >/dev/null

echo "simulation gate runner contract passed"
