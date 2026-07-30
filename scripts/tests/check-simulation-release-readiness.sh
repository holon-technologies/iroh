#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker="$repo_root/scripts/check-simulation-release-readiness.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
mkdir -p "$fixture_root/bin"

repository=holon-technologies/iroh
revision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
now_unix_secs=$(date -u -d '2026-07-26T12:00:00Z' '+%s')

checks="$fixture_root/checks.json"
jq -n --arg revision "$revision" '{
  total_count: 3,
  check_runs: [
    {
      name: "Deterministic simulation change gate",
      head_sha: $revision,
      status: "completed",
      conclusion: "success",
      app: {slug: "github-actions"}
    },
    {
      name: "Deterministic simulation contracts and corpus",
      head_sha: $revision,
      status: "completed",
      conclusion: "success",
      app: {slug: "github-actions"}
    },
    {
      name: "netsim-release / Netsim",
      head_sha: $revision,
      status: "completed",
      conclusion: "success",
      app: {slug: "github-actions"}
    }
  ]
}' >"$checks"

issues="$fixture_root/issues.json"
printf '%s\n' '{"total_count":0,"incomplete_results":false,"items":[]}' >"$issues"

parity="$fixture_root/parity.json"
jq -n '[{
  databaseId: 91,
  headSha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  createdAt: "2026-07-25T04:47:00Z",
  conclusion: "success",
  event: "schedule"
}]' >"$parity"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'if [[ "$1" == api && "$*" == *check-runs* ]]; then' \
  '  jq -c . "$FAKE_RELEASE_CHECKS"' \
  '  exit 0' \
  'fi' \
  'if [[ "$1 $2" == "api search/issues" ]]; then' \
  '  jq -c . "$FAKE_RELEASE_ISSUES"' \
  '  exit 0' \
  'fi' \
  'if [[ "$1 $2" == "run list" ]]; then' \
  '  jq -c . "$FAKE_RELEASE_PARITY"' \
  '  exit 0' \
  'fi' \
  'exit 64' \
  >"$fixture_root/bin/gh"
chmod +x "$fixture_root/bin/gh"
export PATH="$fixture_root/bin:$PATH"
export FAKE_RELEASE_CHECKS="$checks"
export FAKE_RELEASE_ISSUES="$issues"
export FAKE_RELEASE_PARITY="$parity"

invalid_time_output="$fixture_root/invalid-time.json"
set +e
"$checker" \
  --repository "$repository" \
  --revision "$revision" \
  --now-unix-secs 999999999999999999999999999999 \
  --policy "$repo_root/krikos-sim/operations-policy.json" \
  --output "$invalid_time_output"
invalid_time_status=$?
set -e
if [[ "$invalid_time_status" -ne 64 || -e "$invalid_time_output" ]]; then
  echo "release readiness must reject timestamps outside signed 64-bit range" >&2
  exit 1
fi

run_checker() {
  local output=$1
  "$checker" \
    --repository "$repository" \
    --revision "$revision" \
    --now-unix-secs "$now_unix_secs" \
    --policy "$repo_root/krikos-sim/operations-policy.json" \
    --output "$output"
}

success="$fixture_root/success.json"
run_checker "$success"
jq -e \
  --arg revision "$revision" '
    .schema_version == 1
    and .status == "release_ready"
    and .revision == $revision
    and .required_checks == [
      "Deterministic simulation change gate",
      "Deterministic simulation contracts and corpus",
      "netsim-release / Netsim"
    ]
    and .open_product_failures == []
    and .parity.workflow_run_id == 91
    and .parity.source_revision == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  ' "$success" >/dev/null

assert_blocked() {
  local name=$1
  local output="$fixture_root/$name-report.json"
  set +e
  run_checker "$output"
  local status=$?
  set -e
  if [[ "$status" -ne 1 ]]; then
    printf 'release readiness %s returned %s instead of 1\n' "$name" "$status" >&2
    exit 1
  fi
  jq -e '.schema_version == 1 and .status == "release_blocked"' "$output" >/dev/null
}

missing_check="$fixture_root/missing-check.json"
jq '.total_count = 2 | .check_runs = [.check_runs[] | select(.name != "netsim-release / Netsim")]' \
  "$checks" >"$missing_check"
export FAKE_RELEASE_CHECKS="$missing_check"
assert_blocked missing-check
export FAKE_RELEASE_CHECKS="$checks"

open_issue="$fixture_root/open-issue.json"
jq -n '{
  total_count: 1,
  incomplete_results: false,
  items: [{
    number: 42,
    html_url: "https://github.com/holon-technologies/iroh/issues/42",
    body: "<!-- krikos-sim-signature:1111111111111111111111111111111111111111111111111111111111111111 -->",
    labels: [{name: "simulation"}]
  }]
}' >"$open_issue"
export FAKE_RELEASE_ISSUES="$open_issue"
assert_blocked open-product-failure
export FAKE_RELEASE_ISSUES="$issues"

stale_parity="$fixture_root/stale-parity.json"
jq '.[0].createdAt = "2026-06-01T04:47:00Z"' "$parity" >"$stale_parity"
export FAKE_RELEASE_PARITY="$stale_parity"
assert_blocked stale-parity

echo "simulation release readiness contract passed"
