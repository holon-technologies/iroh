#!/usr/bin/env bash

set -euo pipefail

selection=
sim_bin=
artifacts=
jobs=

usage() {
  printf '%s\n' \
    'Usage: run-simulation-gate.sh --selection PATH --sim-bin PATH --artifacts PATH --jobs N'
}

while (($# > 0)); do
  case "$1" in
    --selection)
      selection=$2
      shift 2
      ;;
    --sim-bin)
      sim_bin=$2
      shift 2
      ;;
    --artifacts)
      artifacts=$2
      shift 2
      ;;
    --jobs)
      jobs=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown simulation gate runner argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$selection" || -z "$sim_bin" || -z "$artifacts" || -z "$jobs" ]]; then
  echo "all simulation gate runner arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! -f "$selection" || -L "$selection" ]]; then
  echo "simulation gate selection is missing or unsafe" >&2
  exit 66
fi
if [[ ! -x "$sim_bin" ]]; then
  echo "simulation gate binary is not executable" >&2
  exit 66
fi
if [[ ! "$jobs" =~ ^[0-9]+$ ]] || ((jobs < 1 || jobs > 4)); then
  echo "--jobs must be in 1..=4" >&2
  exit 64
fi
if [[ -e "$artifacts" || -L "$artifacts" ]]; then
  echo "simulation gate artifact root must not already exist" >&2
  exit 73
fi
if (( $(stat -c %s "$selection") > 16777216 )); then
  echo "simulation gate selection exceeds the byte bound" >&2
  exit 65
fi

if ! jq -e '
  def digest: type == "string" and test("^[0-9a-f]{64}$");
  def revision: type == "string" and test("^[0-9a-f]{40}$");
  def swarm($domain):
    if $domain == "direct" then "krikos-sim/swarms/direct-smoke.json"
    elif $domain == "discovery" then "krikos-sim/swarms/discovery-timing.json"
    elif $domain == "mobility" then "krikos-sim/swarms/mobility-timing.json"
    elif $domain == "nat" then "krikos-sim/swarms/nat-behavior.json"
    elif $domain == "ready-order" then "krikos-sim/swarms/ready-order-pressure.json"
    elif $domain == "relay" then "krikos-sim/swarms/relay-lifecycle.json"
    else null
    end;
  def valid_work($kind):
    type == "object"
    and .kind == $kind
    and (.domain | type == "string" and swarm(.) != null)
    and .swarm == swarm(.domain)
    and (.crypto == "deterministic_test" or .crypto == "production_provider")
    and .lane == (
      .domain + "/" +
      (if .crypto == "deterministic_test" then "deterministic-test"
       else "production-provider" end)
    )
    and (.ordinal | type == "number" and . >= 0 and floor == . and . < 8)
    and (.seed_blake3 | digest)
    and (.seed_range | type == "string" and test("^[0-9]+\\.\\.[0-9]+$"));

  type == "object"
  and .schema_version == 1
  and (.impact_policy_id | type == "string" and length > 0 and length <= 128)
  and (.impact_policy_blake3 | digest)
  and (.coverage_policy_blake3 | digest)
  and (.tier == "pull_request" or .tier == "main")
  and (.base_revision | revision)
  and (.candidate_revision | revision)
  and (.mode == "mapped" or .mode == "global_fallback")
  and (.changed_paths | type == "array" and length <= 4096)
  and (.impacted_domains | type == "array" and length <= 6)
  and (.maximum_total_runs | type == "number" and . >= 12 and . <= 64 and floor == .)
  and (.universal | type == "array" and length == 12)
  and all(.universal[]; valid_work("universal"))
  and (.targeted | type == "array")
  and all(.targeted[]; valid_work("targeted"))
  and ((.universal | length) + (.targeted | length) <= .maximum_total_runs)
  and (.universal | map(.lane)) == [
    "direct/deterministic-test",
    "direct/production-provider",
    "discovery/deterministic-test",
    "discovery/production-provider",
    "mobility/deterministic-test",
    "mobility/production-provider",
    "nat/deterministic-test",
    "nat/production-provider",
    "ready-order/deterministic-test",
    "ready-order/production-provider",
    "relay/deterministic-test",
    "relay/production-provider"
  ]
' "$selection" >/dev/null; then
  echo "simulation gate selection is malformed or exceeds its bounds" >&2
  exit 65
fi

if [[ "$artifacts" != /* ]]; then
  artifacts="$PWD/$artifacts"
fi
mkdir -p "$artifacts"
cp "$selection" "$artifacts/gate-selection.json"
failures="$artifacts/failures.jsonl"
: >"$failures"
configured_runs=$(jq -r '(.universal | length) + (.targeted | length)' "$selection")
completed_runs=0
product_failures=0
infrastructure_failures=0

while IFS=$'\t' read -r index encoded; do
  work=$(printf '%s' "$encoded" | base64 --decode)
  kind=$(jq -r '.kind' <<<"$work")
  lane=$(jq -r '.lane' <<<"$work")
  swarm=$(jq -r '.swarm' <<<"$work")
  crypto=$(jq -r '.crypto | gsub("_"; "-")' <<<"$work")
  seed_range=$(jq -r '.seed_range' <<<"$work")
  work_root="$artifacts/work-$(printf '%03d' "$index")"
  mkdir -p "$work_root"

  set +e
  "$sim_bin" campaign \
    --swarm "$swarm" \
    --crypto "$crypto" \
    --seeds "$seed_range" \
    --jobs "$jobs" \
    --continue-on-failure \
    --max-runs 1 \
    --artifacts "$work_root/run" \
    > >(tee "$work_root/stdout.log") \
    2> >(tee "$work_root/stderr.log" >&2)
  work_status=$?
  set -e
  completed_runs=$((completed_runs + 1))
  if [[ "$work_status" -eq 0 ]]; then
    continue
  fi
  classification=infrastructure
  evidence=exit_code
  if [[ "$work_status" -eq 74 ]]; then
    campaign_summary="$work_root/run/campaign-summary.json"
    seed_start=${seed_range%%..*}
    if [[ -f "$campaign_summary" && ! -L "$campaign_summary" \
          && $(stat -c %s "$campaign_summary") -le 16777216 ]] \
      && jq -e \
        --argjson seed_start "$seed_start" \
        --argjson jobs "$jobs" '
          type == "object"
          and (.config | type == "object")
          and .config.seed_start == $seed_start
          and .config.seed_end_exclusive == ($seed_start + 1)
          and .config.jobs == $jobs
          and .config.fail_fast == false
          and .config.max_runs == 1
          and (.results | type == "array" and length == 1)
          and .results[0].seed == $seed_start
          and .results[0].error == null
          and .results[0].worker_panic == false
          and (.results[0].terminal | type == "object")
          and .results[0].terminal.terminal == "failure"
          and (.unique_failures | type == "array" and length >= 1 and length <= 1)
          and .stopped_early == false
        ' "$campaign_summary" >/dev/null 2>&1; then
      classification=product_correctness
      evidence=campaign_summary
      product_failures=$((product_failures + 1))
    else
      evidence=missing_or_invalid_campaign_summary
      infrastructure_failures=$((infrastructure_failures + 1))
    fi
  else
    infrastructure_failures=$((infrastructure_failures + 1))
  fi
  jq -cn \
    --argjson index "$index" \
    --argjson exit_code "$work_status" \
    --arg kind "$kind" \
    --arg lane "$lane" \
    --arg seed_range "$seed_range" \
    --arg classification "$classification" \
    --arg evidence "$evidence" \
    '{
      index: $index,
      exit_code: $exit_code,
      kind: $kind,
      lane: $lane,
      seed_range: $seed_range,
      classification: $classification,
      evidence: $evidence
    }' >>"$failures"
done < <(
  jq -r '
    (.universal + .targeted)
    | to_entries[]
    | [.key, (.value | @base64)]
    | @tsv
  ' "$selection"
)

status=success
exit_status=0
if ((infrastructure_failures > 0)); then
  status=infrastructure_failure
  exit_status=2
elif ((product_failures > 0)); then
  status=product_failure
  exit_status=1
fi
jq -s \
  --arg status "$status" \
  --argjson configured_runs "$configured_runs" \
  --argjson completed_runs "$completed_runs" \
  --argjson product_failures "$product_failures" \
  --argjson infrastructure_failures "$infrastructure_failures" \
  '{
    schema_version: 1,
    status: $status,
    configured_runs: $configured_runs,
    completed_runs: $completed_runs,
    product_failures: $product_failures,
    infrastructure_failures: $infrastructure_failures,
    failures: .
  }' "$failures" >"$artifacts/gate-summary.json"

exit "$exit_status"
