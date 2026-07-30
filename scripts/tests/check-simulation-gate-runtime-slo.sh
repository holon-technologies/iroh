#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
auditor="$repo_root/scripts/audit-simulation-gate-runtime-slo.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
mkdir -p "$fixture_root/bin"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'if [[ "$1 $2" == "run list" ]]; then' \
  '  event=' \
  '  while (($# > 0)); do' \
  '    if [[ "$1" == --event ]]; then event=$2; shift 2; else shift; fi' \
  '  done' \
  '  offset=0' \
  '  [[ "$event" == push ]] && offset=100' \
  '  jq -n --arg event "$event" --argjson count "$FAKE_SLO_RUN_COUNT" --argjson offset "$offset" '\''[
  ' \
  '    range(0; $count) as $index' \
  '    | {' \
  '        databaseId: ($offset + $index + 1),' \
  '        headSha: ("a" * 40),' \
  '        createdAt: "2026-07-25T00:00:00Z",' \
  '        conclusion: "success",' \
  '        event: $event' \
  '      }' \
  '  ]'\''' \
  '  exit 0' \
  'fi' \
  'if [[ "$1 $2" == "run view" ]]; then' \
  '  run_id=$3' \
  '  event=pull_request' \
  '  duration=$FAKE_SLO_PR_SECONDS' \
  '  if ((run_id > 100)); then event=push; duration=$FAKE_SLO_MAIN_SECONDS; fi' \
  '  jq -n --argjson run_id "$run_id" --arg event "$event" --argjson duration "$duration" '\''{' \
  '    databaseId: $run_id,' \
  '    headSha: ("a" * 40),' \
  '    conclusion: "success",' \
  '    event: $event,' \
  '    jobs: [' \
  '      {' \
  '        name: "Deterministic simulation change gate",' \
  '        startedAt: "2026-07-25T00:00:00Z",' \
  '        completedAt: (("2026-07-25T00:00:00Z" | fromdateiso8601) + $duration | todateiso8601),' \
  '        conclusion: "success"' \
  '      },' \
  '      {' \
  '        name: "Deterministic simulation contracts and corpus",' \
  '        startedAt: "2026-07-25T00:00:00Z",' \
  '        completedAt: (("2026-07-25T00:00:00Z" | fromdateiso8601) + $duration | todateiso8601),' \
  '        conclusion: "success"' \
  '      }' \
  '    ]' \
  '  }'\''' \
  '  exit 0' \
  'fi' \
  'exit 64' \
  >"$fixture_root/bin/gh"
chmod +x "$fixture_root/bin/gh"
export PATH="$fixture_root/bin:$PATH"
export FAKE_SLO_RUN_COUNT=20
export FAKE_SLO_PR_SECONDS=600
export FAKE_SLO_MAIN_SECONDS=1200

run_auditor() {
  local output=$1
  "$auditor" \
    --repository holon-technologies/iroh \
    --now-unix-secs "$(date -u -d '2026-07-26T12:00:00Z' '+%s')" \
    --policy "$repo_root/krikos-sim/operations-policy.json" \
    --output "$output"
}

success="$fixture_root/success.json"
run_auditor "$success"
jq -e '
  .schema_version == 1
  and .status == "within_slo"
  and .sample_size == 20
  and .percentile == 95
  and (.tiers | map(.tier)) == ["main", "pull_request"]
  and (.tiers | all(.samples == 20 and (.workflow_run_ids | length) == 20))
  and (.tiers | any(
    .tier == "main" and .event == "push" and .p95_seconds == 1200
    and .maximum_seconds == 1800 and .status == "within_slo"
  ))
  and (.tiers | any(
    .tier == "pull_request" and .event == "pull_request" and .p95_seconds == 600
    and .maximum_seconds == 900 and .status == "within_slo"
  ))
' "$success" >/dev/null

export FAKE_SLO_RUN_COUNT=19
insufficient="$fixture_root/insufficient.json"
run_auditor "$insufficient"
jq -e '
  .status == "insufficient_history"
  and all(.tiers[]; .samples == 19 and .status == "insufficient_history")
' "$insufficient" >/dev/null

export FAKE_SLO_RUN_COUNT=20
export FAKE_SLO_PR_SECONDS=901
breach="$fixture_root/breach.json"
set +e
run_auditor "$breach"
breach_status=$?
set -e
if [[ "$breach_status" -ne 1 ]]; then
  printf 'simulation runtime SLO breach returned %s instead of 1\n' "$breach_status" >&2
  exit 1
fi
jq -e '
  .status == "slo_breach"
  and (.tiers | any(.tier == "pull_request" and .p95_seconds == 901 and .status == "slo_breach"))
' "$breach" >/dev/null

echo "simulation gate runtime SLO contract passed"
