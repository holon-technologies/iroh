#!/usr/bin/env bash

set -euo pipefail

rolling=
plan=
maximum_lanes=
output=

usage() {
  printf '%s\n' \
    'Usage: select-simulation-gaps.sh --rolling PATH --plan PATH --max-lanes N --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --rolling)
      rolling=$2
      shift 2
      ;;
    --plan)
      plan=$2
      shift 2
      ;;
    --max-lanes)
      maximum_lanes=$2
      shift 2
      ;;
    --output)
      output=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown simulation gap selection argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$rolling" || -z "$plan" || -z "$maximum_lanes" || -z "$output" ]]; then
  echo '--rolling, --plan, --max-lanes, and --output are required' >&2
  usage >&2
  exit 64
fi
if [[ ! "$maximum_lanes" =~ ^[0-9]+$ ]] || ((maximum_lanes < 1 || maximum_lanes > 32)); then
  echo '--max-lanes must be in 1..=32' >&2
  exit 64
fi
for input in "$rolling" "$plan"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    printf 'simulation gap selection input is missing or unsafe: %s\n' "$input" >&2
    exit 66
  fi
done
if [[ "$output" != /* ]]; then
  output="$PWD/$output"
fi
mkdir -p "$(dirname "$output")"

if ! jq -e '
  .schema_version == 1
  and (.policy_blake3 | type == "string" and test("^[0-9a-f]{64}$"))
  and (.gaps | type == "array" and length <= 100000)
' "$rolling" >/dev/null; then
  echo 'rolling simulation coverage report is malformed' >&2
  exit 65
fi
if ! jq -e '
  .schema_version == 2
  and (.coverage_policy_blake3 | type == "string" and test("^[0-9a-f]{64}$"))
  and (.lanes | type == "array" and length > 0 and length <= 32)
' "$plan" >/dev/null; then
  echo 'simulation soak plan is malformed' >&2
  exit 65
fi

rolling_policy=$(jq -r '.policy_blake3' "$rolling")
plan_policy=$(jq -r '.coverage_policy_blake3' "$plan")
if [[ "$rolling_policy" != "$plan_policy" ]]; then
  echo 'rolling coverage and soak plan policy revisions differ' >&2
  exit 65
fi

temporary="$output.tmp.$$"
jq -n \
  --slurpfile rolling "$rolling" \
  --slurpfile plan "$plan" \
  --argjson maximum_lanes "$maximum_lanes" \
  '
    def provider_suffix($provider):
      if $provider == "deterministic_test" then "deterministic-test"
      elif $provider == "production_provider" then "production-provider"
      else null
      end;
    def assignment($gap):
      if $gap.class == "individual"
         or $gap.class == "higher_order"
         or $gap.class == "transition"
         or $gap.class == "oracle"
         or $gap.class == "phase" then
        {domain: $gap.bucket.domain, provider: $gap.bucket.provider}
      elif $gap.class == "pair" then
        {domain: $gap.bucket.first.domain, provider: $gap.bucket.first.provider}
      else null
      end;
    def priority($class):
      if $class == "higher_order" then 0
      elif $class == "transition" then 1
      elif $class == "pair" then 2
      elif $class == "individual" then 3
      elif $class == "phase" then 4
      elif $class == "oracle" then 5
      else 6
      end;

    $rolling[0] as $rolling_report
    | $plan[0] as $soak_plan
    | ([
        $rolling_report.gaps[]
        | . as $gap
        | assignment($gap) as $assignment
        | select($assignment != null)
        | provider_suffix($assignment.provider) as $suffix
        | select($suffix != null)
        | ($assignment.domain + "/" + $suffix) as $lane
        | select(any($soak_plan.lanes[]; .id == $lane))
        | {
            lane: $lane,
            priority: priority($gap.class),
            gap_class: $gap.class
          }
      ]
      | sort_by(.priority, .lane)
      | group_by(.lane)
      | map({
          lane: .[0].lane,
          priority: (map(.priority) | min),
          gap_classes: (map(.gap_class) | unique | sort),
          gap_count: length
        })
      | sort_by(.priority, .lane)
      | .[:$maximum_lanes]) as $lanes
    | {
        schema_version: 1,
        policy_id: $rolling_report.policy_id,
        policy_blake3: $rolling_report.policy_blake3,
        maximum_lanes: $maximum_lanes,
        lanes: ($lanes | sort_by(.lane)),
        unassigned_gaps: [
          $rolling_report.gaps[]
          | . as $gap
          | assignment($gap) as $assignment
          | if $assignment == null then $gap
            else
              provider_suffix($assignment.provider) as $suffix
              | if $suffix == null
                   or (any($soak_plan.lanes[]; .id == ($assignment.domain + "/" + $suffix)) | not)
                then $gap
                else empty
                end
            end
        ]
      }
  ' >"$temporary"
mv "$temporary" "$output"
