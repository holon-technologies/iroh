#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
collector="$repo_root/scripts/collect-simulation-coverage-history.sh"

if [[ ! -x "$collector" ]]; then
  echo "simulation coverage history collector is missing or not executable" >&2
  exit 1
fi
bash -n "$collector"

fixture_root=$(mktemp -d)
fake_bin="$fixture_root/bin"
fake_fixtures="$fixture_root/fixtures"
mkdir -p "$fake_bin" "$fake_fixtures/41" "$fake_fixtures/40" "$fake_fixtures/39"

cat >"$fake_bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_GH_LOG"
printf '\n' >>"$FAKE_GH_LOG"
if [[ "$1 $2" == "run list" ]]; then
  printf '%s\n' "$FAKE_GH_RUNS"
  exit 0
fi
if [[ "$1 $2" == "run download" ]]; then
  run_id=$3
  shift 3
  destination=
  artifact_name=
  while (($# > 0)); do
    case "$1" in
      --dir)
        destination=$2
        shift 2
        ;;
      --name)
        artifact_name=$2
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
  if [[ "$run_id" == 38 ]]; then
    if [[ "$artifact_name" == "iroh-sim-daily-soak-38" ]]; then
      mkdir -p "$destination"
      exit 0
    fi
    exit 1
  fi
  mkdir -p "$destination"
  cp "$FAKE_GH_FIXTURES/$run_id/daily-soak-aggregate.json" "$destination/"
  exit 0
fi
exit 64
FAKE_GH
chmod +x "$fake_bin/gh"

policy_digest=8e275709a3bb949f570c51abf184e023bb8a618f3d8aa8cbbfa737d9cdfe52c2
write_report() {
  local output=$1
  local run_id=$2
  local revision=$3
  local observed_at=$4

  jq -n \
    --argjson run_id "$run_id" \
    --arg revision "$revision" \
    --argjson observed_at "$observed_at" \
    --arg policy_digest "$policy_digest" \
    '{
      schema_version: 1,
      source_revision: $revision,
      workflow_run_id: $run_id,
      observed_at_unix_secs: $observed_at,
      coverage: {
        schema_version: 2,
        policy_blake3: $policy_digest
      }
    }' >"$output"
}

revision_41=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
revision_40=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
write_report \
  "$fake_fixtures/41/daily-soak-aggregate.json" \
  41 \
  "$revision_41" \
  190000
write_report \
  "$fake_fixtures/40/daily-soak-aggregate.json" \
  40 \
  "$revision_40" \
  180000
# A report emitted before coverage-policy provenance existed is outside the current
# policy window. Rollout must skip it instead of turning seven days of legacy history
# into an infrastructure incident.
jq -n \
  --argjson run_id 39 \
  --arg revision cccccccccccccccccccccccccccccccccccccccc \
  --argjson observed_at 175000 \
  '{
    schema_version: 1,
    source_revision: $revision,
    workflow_run_id: $run_id,
    observed_at_unix_secs: $observed_at
  }' >"$fake_fixtures/39/daily-soak-aggregate.json"

export PATH="$fake_bin:$PATH"
export FAKE_GH_LOG="$fixture_root/gh.log"
export FAKE_GH_FIXTURES="$fake_fixtures"
export FAKE_GH_RUNS='[
  {
    "databaseId": 42,
    "headSha": "cccccccccccccccccccccccccccccccccccccccc",
    "createdAt": "1970-01-03T07:33:20Z"
  },
  {
    "databaseId": 41,
    "headSha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "createdAt": "1970-01-03T04:46:40Z"
  },
  {
    "databaseId": 40,
    "headSha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "createdAt": "1970-01-03T02:00:00Z"
  },
  {
    "databaseId": 39,
    "headSha": "cccccccccccccccccccccccccccccccccccccccc",
    "createdAt": "1970-01-03T00:36:40Z"
  },
  {
    "databaseId": 38,
    "headSha": "dddddddddddddddddddddddddddddddddddddddd",
    "createdAt": "1970-01-02T23:46:40Z"
  }
]'

history="$fixture_root/history"
"$collector" \
  --repository holon-technologies/iroh \
  --workflow simulation-daily-soak.yml \
  --current-run-id 42 \
  --policy-blake3 "$policy_digest" \
  --window-start-unix-secs 170000 \
  --window-end-unix-secs 200000 \
  --output "$history"

mapfile -t collected < <(find "$history" -maxdepth 1 -type f -name '*.json' -printf '%f\n' | sort)
if [[ "${collected[*]}" != "40.json 41.json" ]]; then
  printf 'unexpected collected history: %s\n' "${collected[*]}" >&2
  exit 1
fi
jq -e '.workflow_run_id == 40' "$history/40.json" >/dev/null
jq -e '.workflow_run_id == 41' "$history/41.json" >/dev/null
grep -Fq -- '--limit 32' "$FAKE_GH_LOG"
grep -Fq -- '--status completed' "$FAKE_GH_LOG"
grep -Fq -- '--repo holon-technologies/iroh' "$FAKE_GH_LOG"
grep -Fq -- 'iroh-sim-daily-soak-38' "$FAKE_GH_LOG"

# GitHub metadata and immutable aggregate provenance must agree.
jq '.source_revision = "dddddddddddddddddddddddddddddddddddddddd"' \
  "$fake_fixtures/41/daily-soak-aggregate.json" \
  >"$fake_fixtures/41/daily-soak-aggregate.json.tmp"
mv \
  "$fake_fixtures/41/daily-soak-aggregate.json.tmp" \
  "$fake_fixtures/41/daily-soak-aggregate.json"
mismatch_history="$fixture_root/mismatch-history"
set +e
"$collector" \
  --repository holon-technologies/iroh \
  --workflow simulation-daily-soak.yml \
  --current-run-id 42 \
  --policy-blake3 "$policy_digest" \
  --window-start-unix-secs 170000 \
  --window-end-unix-secs 200000 \
  --output "$mismatch_history"
mismatch_status=$?
set -e
if [[ "$mismatch_status" -ne 2 ]]; then
  echo "collector must classify provenance mismatch as infrastructure failure" >&2
  exit 1
fi

echo "simulation coverage history collector contract passed"
